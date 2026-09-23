"""Mot de passe oublié et envoi d'e-mails (boîte d'envoi locale sans SMTP)."""
import email
import re
from email import policy

from conftest import PASSWORD, register

NEW_PASSWORD = "Nouveau-Passw0rd-99"


def _outbox(service) -> list[email.message.EmailMessage]:
    folder = service.settings.data_dir / "outbox"
    if not folder.exists():
        return []
    return [email.message_from_bytes(p.read_bytes(), policy=policy.default) for p in sorted(folder.glob("*.eml"))]


def _link(message) -> str:
    return re.search(r"https?://\S+", message.get_content()).group(0)


def test_reset_flow(api, service):
    user = register(api(), "jane.doe@example.com")
    resp = api().post("/api/auth/password-reset", json={"email": "jane.doe@example.com"})
    assert resp.status_code == 200
    [mail] = _outbox(service)
    assert mail["To"] == "jane.doe@example.com" and "réinitialisation" in mail["Subject"]
    token = _link(mail).rsplit("/", 1)[1]

    anonymous = api()
    assert anonymous.post(f"/api/auth/password-reset/{token}", json={"password": "faible"}).status_code == 400
    assert anonymous.post(f"/api/auth/password-reset/{token}", json={"password": NEW_PASSWORD}).status_code == 200
    # Lien à usage unique, anciennes sessions fermées, ancien mot de passe refusé
    assert anonymous.post(f"/api/auth/password-reset/{token}", json={"password": NEW_PASSWORD}).status_code == 404
    assert user.get("/api/auth/me").status_code == 401
    login = api()
    assert login.post("/api/auth/login", json={"email": "jane.doe@example.com", "password": PASSWORD}).status_code == 401
    assert login.post("/api/auth/login", json={"email": "jane.doe@example.com", "password": NEW_PASSWORD}).status_code == 200
    assert any(e["action"] == "member.password_reset" for e in login.get("/api/audit").json())


def test_reset_does_not_reveal_accounts(api, service):
    register(api(), "jane.doe@example.com")
    known = api().post("/api/auth/password-reset", json={"email": "jane.doe@example.com"})
    unknown = api().post("/api/auth/password-reset", json={"email": "nobody@example.com"})
    assert known.status_code == unknown.status_code == 200 and known.json() == unknown.json()
    assert [m["To"] for m in _outbox(service)] == ["jane.doe@example.com"]


def test_reset_rate_limited(api):
    client = api()
    for _ in range(3):
        assert client.post("/api/auth/password-reset", json={"email": "jane.doe@example.com"}).status_code == 200
    assert client.post("/api/auth/password-reset", json={"email": "jane.doe@example.com"}).status_code == 429


def test_new_request_invalidates_previous_link(api, service):
    register(api(), "jane.doe@example.com")
    api().post("/api/auth/password-reset", json={"email": "jane.doe@example.com"})
    api().post("/api/auth/password-reset", json={"email": "jane.doe@example.com"})
    first, second = (_link(m).rsplit("/", 1)[1] for m in _outbox(service))
    assert api().post(f"/api/auth/password-reset/{first}", json={"password": NEW_PASSWORD}).status_code == 404
    assert api().post(f"/api/auth/password-reset/{second}", json={"password": NEW_PASSWORD}).status_code == 200


def test_reset_token_not_stored_in_clear(api, service):
    import sqlite3

    register(api(), "jane.doe@example.com")
    api().post("/api/auth/password-reset", json={"email": "jane.doe@example.com"})
    token = _link(_outbox(service)[0]).rsplit("/", 1)[1]
    dump = "\n".join(sqlite3.connect(service.storage.db_path).iterdump())
    assert token not in dump


def test_invitation_email(api, service):
    owner = register(api(), "owner@example.com")
    resp = owner.post("/api/org/invitations", json={"email": "dev@example.com", "role": "member"}).json()
    assert resp["email_sent"] is False and "boîte d'envoi locale" in resp["email_detail"]
    [mail] = _outbox(service)
    assert mail["To"] == "dev@example.com" and "Acme Corp" in mail["Subject"]
    assert _link(mail) == resp["url"]
