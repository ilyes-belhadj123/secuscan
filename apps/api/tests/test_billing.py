"""SS-20 — offres, quotas, changement d'offre, facturation et webhook."""
import hashlib
import hmac
import json

import pytest
from conftest import register

from secuscan.billing import verify_signature


def _snippet(client, project="Extrait de code"):
    return client.post("/api/scans/snippet", json={"filename": "a.py", "code": "eval(x)\n", "project_name": project})


@pytest.fixture
def free_org(api):
    register(api(), "owner@example.com", org_name="Première org")  # 1re organisation : offre Business
    client = register(api(), "jane.doe@example.com", org_name="Acme Corp")
    assert client.get("/api/auth/me").json()["org"]["plan"] == "free"
    return client


def test_first_org_is_business_others_free(api):
    first = register(api(), "owner@example.com", org_name="Première org")
    assert first.get("/api/auth/me").json()["org"]["plan"] == "business"


def test_free_monthly_scan_quota(free_org):
    for _ in range(5):
        assert _snippet(free_org).status_code == 202
    resp = _snippet(free_org)
    assert resp.status_code == 402 and "5 analyses par mois" in resp.json()["detail"]
    assert free_org.get("/api/billing").json()["usage"]["scans_this_month"] == 5


def test_free_project_quota(free_org):
    assert _snippet(free_org, "Portail client").status_code == 202
    assert _snippet(free_org, "Portail client").status_code == 202  # même projet : autorisé
    resp = _snippet(free_org, "API interne")
    assert resp.status_code == 402 and "1 projet" in resp.json()["detail"]
    assert _snippet(free_org, "Extrait de code").status_code == 202  # extraits et démo hors quota de projets


def test_free_member_quota(free_org):
    for email in ("a@example.com", "b@example.com"):
        assert free_org.post("/api/org/invitations", json={"email": email, "role": "member"}).status_code == 201
    resp = free_org.post("/api/org/invitations", json={"email": "c@example.com", "role": "member"})
    assert resp.status_code == 402


def test_white_label_requires_business(free_org, service):
    _snippet(free_org)
    service.executor.shutdown(wait=True)  # attendre la fin de l'analyse en tâche de fond
    scan_id = free_org.get("/api/scans").json()[0]["id"]
    assert free_org.get(f"/api/scans/{scan_id}/report.pdf").status_code == 200
    resp = free_org.get(f"/api/scans/{scan_id}/report.pdf", params={"prepared_by": "Exemple Conseil"})
    assert resp.status_code == 402


def test_upgrade_creates_invoice_and_lifts_quota(free_org):
    for _ in range(5):
        _snippet(free_org)
    resp = free_org.post("/api/billing/plan", json={"plan": "pro"})
    assert resp.status_code == 200
    invoice = resp.json()["invoice"]
    assert invoice["plan"] == "pro" and invoice["amount_eur"] == invoice["unit_price_eur"] * invoice["seats"]
    assert "démo" in invoice["status"]
    assert _snippet(free_org).status_code == 202  # quota Pro : 100 analyses par mois
    billing = free_org.get("/api/billing").json()
    assert billing["plan"] == "pro" and len(billing["invoices"]) == 1
    assert any(e["action"] == "billing.plan_changed" for e in free_org.get("/api/audit").json())


def test_only_owner_changes_plan(api, free_org):
    token = free_org.post("/api/org/invitations", json={"email": "admin@example.com", "role": "admin"}).json()["url"]
    admin = register(api(), "admin@example.com", org_name=None, invitation_token=token.rsplit("/", 1)[1])
    assert admin.post("/api/billing/plan", json={"plan": "business"}).status_code == 403


def test_downgrade_blocked_when_usage_exceeds_limits(api, free_org):
    free_org.post("/api/billing/plan", json={"plan": "pro"})
    for email in ("a@example.com", "b@example.com", "c@example.com"):
        token = free_org.post("/api/org/invitations", json={"email": email, "role": "member"}).json()["url"]
        register(api(), email, org_name=None, invitation_token=token.rsplit("/", 1)[1])
    resp = free_org.post("/api/billing/plan", json={"plan": "free"})
    assert resp.status_code == 409 and "retirez d'abord 1 membre" in resp.json()["detail"]


def test_scan_ai_budget_follows_org_plan(free_org):
    scan = _snippet(free_org).json()
    assert scan["plan"] == "free"


# ---------------------------------------------------------------------- webhook du prestataire
def _signed(secret: str, payload: dict) -> tuple[bytes, str]:
    body = json.dumps(payload).encode()
    return body, "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def test_signature_verification():
    body, sig = _signed("secret-de-test", {"a": 1})
    assert verify_signature("secret-de-test", body, sig)
    assert not verify_signature("secret-de-test", body + b" ", sig)
    assert not verify_signature("", body, sig)  # webhook désactivé sans secret


def test_webhook_updates_plan(api, service, free_org):
    org_id = free_org.get("/api/auth/me").json()["org"]["id"]
    event = {"type": "subscription.updated", "org_id": org_id, "plan": "business", "provider": "stripe"}

    anonymous = api()
    body, sig = _signed("secret-de-test", event)
    assert anonymous.post("/api/billing/webhook", content=body, headers={"x-secuscan-signature": sig}).status_code == 401

    service.settings.secuscan_billing_webhook_secret = "secret-de-test"
    _, bad = _signed("mauvais-secret", event)
    assert anonymous.post("/api/billing/webhook", content=body, headers={"x-secuscan-signature": bad}).status_code == 401
    assert anonymous.post("/api/billing/webhook", content=body, headers={"x-secuscan-signature": sig}).status_code == 200
    assert free_org.get("/api/auth/me").json()["org"]["plan"] == "business"
    invoice = free_org.get("/api/billing").json()["invoices"][0]
    assert invoice["provider"] == "stripe" and invoice["status"] == "payée"


def test_billing_requires_login(api):
    assert api().get("/api/billing").status_code == 401
    assert api().post("/api/billing/plan", json={"plan": "pro"}).status_code == 401
