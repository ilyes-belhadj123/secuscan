"""SS-2 — comptes, rôles, invitations et isolation multi-tenant."""
import sqlite3

import pytest
from conftest import PASSWORD, register

from secuscan.auth import hash_password, verify_password
from secuscan.models import Scan
from secuscan.pipeline import new_id


def _scan_for(service, client, tmp_path, name="Projet Acme"):
    org_id = client.get("/api/auth/me").json()["org"]["id"]
    project = tmp_path / name
    project.mkdir(parents=True)
    (project / "app.py").write_text("import os\nos.system(cmd)\n", encoding="utf-8")
    scan = Scan(id=new_id(), project_name=name, source="upload", org_id=org_id)
    service.storage.save_scan(scan)
    finding = service.run(scan, project)[0]
    return scan.id, finding.id


# ---------------------------------------------------------------------- mots de passe et sessions
def test_password_hashing():
    stored = hash_password(PASSWORD)
    assert stored.startswith("scrypt$") and PASSWORD not in stored
    assert verify_password(PASSWORD, stored) and not verify_password("Wrong-Passw0rd-42", stored)


def test_routes_require_login(api):
    anonymous = api()
    for path in ("/api/scans", "/api/costs", "/api/audit", "/api/auth/me", "/api/org"):
        assert anonymous.get(path).status_code == 401, path
    assert anonymous.post("/api/scans/demo").status_code == 401
    assert anonymous.get("/api/health").status_code == 200  # seule route publique


def test_weak_password_and_duplicate_email(api):
    client = api()
    resp = client.post("/api/auth/register", json={"name": "Jane", "email": "jane.doe@example.com",
                                                   "password": "motdepasse", "org_name": "Acme Corp"})
    assert resp.status_code == 400
    register(client, "jane.doe@example.com")
    resp = api().post("/api/auth/register", json={"name": "Jane", "email": "JANE.DOE@example.com",
                                                  "password": PASSWORD, "org_name": "Autre"})
    assert resp.status_code == 409


def test_login_logout_and_rate_limit(api):
    register(api(), "jane.doe@example.com")
    client = api()
    assert client.post("/api/auth/login", json={"email": "jane.doe@example.com", "password": PASSWORD}).status_code == 200
    assert client.get("/api/auth/me").json()["user"]["email"] == "jane.doe@example.com"
    client.post("/api/auth/logout")
    assert client.get("/api/auth/me").status_code == 401

    attacker = api()
    for _ in range(5):
        r = attacker.post("/api/auth/login", json={"email": "jane.doe@example.com", "password": "Wrong-Passw0rd-1"})
        assert r.status_code == 401
    blocked = attacker.post("/api/auth/login", json={"email": "jane.doe@example.com", "password": PASSWORD})
    assert blocked.status_code == 429  # bloqué même avec le bon mot de passe


def test_unknown_email_same_error_as_wrong_password(api):
    register(api(), "jane.doe@example.com")
    a = api().post("/api/auth/login", json={"email": "nobody@example.com", "password": PASSWORD})
    b = api().post("/api/auth/login", json={"email": "jane.doe@example.com", "password": "Wrong-Passw0rd-1"})
    assert a.status_code == b.status_code == 401 and a.json() == b.json()


def test_session_token_not_stored_in_clear(api, service):
    client = register(api(), "jane.doe@example.com")
    token = client.cookies.get("secuscan_session")
    dump = "\n".join(sqlite3.connect(service.storage.db_path).iterdump())
    assert token and token not in dump and PASSWORD not in dump


def test_csrf_foreign_origin_rejected(api):
    client = register(api(), "jane.doe@example.com")
    resp = client.post("/api/scans/demo", headers={"Origin": "https://evil.example.com"})
    assert resp.status_code == 403


# ---------------------------------------------------------------------- isolation multi-tenant
def test_cross_tenant_isolation(api, service, tmp_path):
    alice = register(api(), "alice@example.com", org_name="Acme Corp")
    bob = register(api(), "bob@example.com", org_name="Globex")
    scan_id, finding_id = _scan_for(service, alice, tmp_path)

    assert [s["id"] for s in alice.get("/api/scans").json()] == [scan_id]
    assert bob.get("/api/scans").json() == []
    for path in (f"/api/scans/{scan_id}", f"/api/scans/{scan_id}/findings", f"/api/scans/{scan_id}/history",
                 f"/api/scans/{scan_id}/report.pdf", f"/api/scans/{scan_id}/report.json", f"/api/findings/{finding_id}"):
        assert bob.get(path).status_code == 404, path  # introuvable : l'existence n'est pas révélée
    resp = bob.post(f"/api/findings/{finding_id}/dismiss",
                    json={"reason": "false_positive", "justification": "Tentative depuis une autre organisation"})
    assert resp.status_code == 404
    assert bob.get("/api/costs").json()["scans"] == []
    assert all(e["details"].get("project") != "Projet Acme" for e in bob.get("/api/audit").json())


def test_dismissals_are_scoped_to_org(api, service, tmp_path):
    alice = register(api(), "alice@example.com", org_name="Acme Corp")
    bob = register(api(), "bob@example.com", org_name="Globex")
    _, finding_id = _scan_for(service, alice, tmp_path / "a")
    alice.post(f"/api/findings/{finding_id}/dismiss",
               json={"reason": "accepted_risk", "justification": "Décision de l'équipe Acme."})
    # Même projet, même code dans une autre organisation : l'alerte n'y est pas masquée
    bob_org = bob.get("/api/auth/me").json()["org"]["id"]
    project = tmp_path / "b"
    project.mkdir()
    (project / "app.py").write_text("import os\nos.system(cmd)\n", encoding="utf-8")
    scan = Scan(id=new_id(), project_name="Projet Acme", source="upload", org_id=bob_org)
    service.storage.save_scan(scan)
    assert service.run(scan, project)[0].status == "open"


# ---------------------------------------------------------------------- rôles et invitations
@pytest.fixture
def org_with_member(api):
    owner = register(api(), "owner@example.com")
    inv = owner.post("/api/org/invitations", json={"email": "dev@example.com", "role": "member"})
    assert inv.status_code == 201
    token = inv.json()["url"].rsplit("/", 1)[1]
    preview = api().get(f"/api/invitations/{token}").json()
    assert preview["org_name"] == "Acme Corp" and preview["email"] == "dev@example.com"
    member = register(api(), "dev@example.com", org_name=None, invitation_token=token)
    return owner, member, token


def test_invitation_flow(org_with_member, api):
    owner, member, token = org_with_member
    assert member.get("/api/auth/me").json()["org"]["name"] == "Acme Corp"
    members = owner.get("/api/org").json()["members"]
    assert {m["email"]: m["role"] for m in members} == {"owner@example.com": "owner", "dev@example.com": "member"}
    assert api().get(f"/api/invitations/{token}").status_code == 404  # invitation à usage unique


def test_invitation_bound_to_email(api):
    owner = register(api(), "owner@example.com")
    invitation = owner.post("/api/org/invitations", json={"email": "dev@example.com", "role": "admin"}).json()
    token = invitation["url"].rsplit("/", 1)[1]
    resp = api().post("/api/auth/register", json={"name": "Intrus", "email": "intrus@example.com",
                                                  "password": PASSWORD, "invitation_token": token})
    assert resp.status_code == 403


def test_member_permissions(org_with_member):
    owner, member, _ = org_with_member
    assert member.get("/api/audit").status_code == 403
    assert member.post("/api/org/invitations", json={"email": "x@example.com", "role": "member"}).status_code == 403
    owner_id = owner.get("/api/auth/me").json()["user"]["id"]
    assert member.delete(f"/api/org/members/{owner_id}").status_code == 403
    assert member.get("/api/org").json()["invitations"] == []  # les invitations ne sont visibles qu'aux admins


def test_last_owner_is_protected(org_with_member):
    owner, _, _ = org_with_member
    owner_id = owner.get("/api/auth/me").json()["user"]["id"]
    assert owner.patch(f"/api/org/members/{owner_id}", json={"role": "member"}).status_code == 409
    assert owner.delete(f"/api/org/members/{owner_id}").status_code == 409


def test_removed_member_loses_access_immediately(org_with_member):
    owner, member, _ = org_with_member
    member_id = member.get("/api/auth/me").json()["user"]["id"]
    assert owner.delete(f"/api/org/members/{member_id}").status_code == 200
    assert member.get("/api/scans").status_code == 401


def test_admin_cannot_grant_owner(org_with_member):
    owner, member, _ = org_with_member
    member_id = member.get("/api/auth/me").json()["user"]["id"]
    assert owner.patch(f"/api/org/members/{member_id}", json={"role": "admin"}).status_code == 200
    assert member.patch(f"/api/org/members/{member_id}", json={"role": "owner"}).status_code == 403


def test_first_org_claims_legacy_scans(api, service):
    legacy = Scan(id=new_id(), project_name="Ancienne analyse", source="demo")
    internal = Scan(id=new_id(), project_name="benchmark:corpus", source="upload")
    service.storage.save_scan(legacy)
    service.storage.save_scan(internal)
    first = register(api(), "first@example.com")
    names = [s["project_name"] for s in first.get("/api/scans").json()]
    assert names == ["Ancienne analyse"]  # le benchmark interne reste invisible
    second = register(api(), "second@example.com", org_name="Globex")
    assert second.get("/api/scans").json() == []
