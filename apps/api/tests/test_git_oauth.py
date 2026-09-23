"""SS-17 — connexion GitHub (OAuth simulé) : état anti-CSRF, jetons chiffrés, dépôts privés."""
import base64
import os
import sqlite3
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from conftest import register
from cryptography.exceptions import InvalidTag

from secuscan import gitproviders, main
from secuscan.tokenbox import decrypt, encrypt

GH_TOKEN = "gho_FAKE_TEST_TOKEN_0000000000000000"
TOKEN_KEY = base64.b64encode(os.urandom(32)).decode()


def fake_github(request: httpx.Request) -> httpx.Response:
    url = str(request.url)
    if url.startswith("https://github.com/login/oauth/access_token"):
        form = parse_qs(request.content.decode())
        if form.get("code") != ["code-ok"]:
            return httpx.Response(200, json={"error": "bad_verification_code"})
        return httpx.Response(200, json={"access_token": GH_TOKEN, "scope": "repo,read:user", "token_type": "bearer"})
    assert request.headers["Authorization"] == f"Bearer {GH_TOKEN}"
    if url == "https://api.github.com/user":
        return httpx.Response(200, json={"login": "janedoe"})
    if url.startswith("https://api.github.com/user/repos"):
        return httpx.Response(200, json=[{"full_name": "acme/portail-prive", "private": True, "default_branch": "main"}])
    if url == "https://api.github.com/repos/acme/portail-prive":
        return httpx.Response(200, json={"name": "portail-prive", "clone_url": "https://github.com/acme/portail-prive.git",
                                         "default_branch": "main", "private": True})
    if url.startswith("https://api.github.com/repos/acme/portail-prive/branches"):
        return httpx.Response(200, json=[{"name": "main"}, {"name": "develop"}])
    return httpx.Response(404, json={"message": "Not Found"})


@pytest.fixture
def github(monkeypatch, service):
    service.settings.secuscan_github_client_id = "test-client-id"
    service.settings.secuscan_github_client_secret = "test-client-secret"
    service.settings.secuscan_token_key = TOKEN_KEY
    real_client = httpx.Client
    monkeypatch.setattr(gitproviders, "_http", lambda: real_client(transport=httpx.MockTransport(fake_github)))
    return service


def _connect(client) -> None:
    authorize = client.get("/api/git/github/connect").json()["authorize_url"]
    query = parse_qs(urlparse(authorize).query)
    assert query["scope"] == ["repo read:user"] and query["client_id"] == ["test-client-id"]
    resp = client.get("/api/git/github/callback", params={"code": "code-ok", "state": query["state"][0]},
                      follow_redirects=False)
    assert resp.status_code == 303 and "git=connected" in resp.headers["location"]


def test_not_configured(api):
    client = register(api(), "jane.doe@example.com")
    providers = {p["id"]: p for p in client.get("/api/git/providers").json()}
    assert providers["github"]["configured"] is False
    assert client.get("/api/git/github/connect").status_code == 503


def test_oauth_flow_and_encrypted_storage(api, github):
    client = register(api(), "jane.doe@example.com")
    _connect(client)
    github_status = next(p for p in client.get("/api/git/providers").json() if p["id"] == "github")
    assert github_status == {"id": "github", "name": "GitHub", "configured": True, "connected": True, "login": "janedoe"}
    dump = "\n".join(sqlite3.connect(github.storage.db_path).iterdump())
    assert GH_TOKEN not in dump  # jeton chiffré au repos
    assert client.get("/api/git/github/repos").json() == [
        {"id": "acme/portail-prive", "name": "acme/portail-prive", "private": True, "default_branch": "main"}]
    assert client.get("/api/git/github/branches", params={"repo": "acme/portail-prive"}).json() == ["main", "develop"]
    assert any(e["action"] == "git.connected" for e in client.get("/api/audit").json())


def test_callback_rejects_forged_or_reused_state(api, github):
    client = register(api(), "jane.doe@example.com")
    forged = client.get("/api/git/github/callback", params={"code": "code-ok", "state": "etat-invente"},
                        follow_redirects=False)
    assert "git=error" in forged.headers["location"]
    authorize = client.get("/api/git/github/connect").json()["authorize_url"]
    state = parse_qs(urlparse(authorize).query)["state"][0]
    # L'état d'un autre utilisateur ne peut pas être rejoué dans sa session (rattachement de compte forcé)
    attacker = register(api(), "attaquant@example.com", org_name="Autre org")
    hijack = attacker.get("/api/git/github/callback", params={"code": "code-ok", "state": state}, follow_redirects=False)
    assert "git=error" in hijack.headers["location"]
    replay = client.get("/api/git/github/callback", params={"code": "code-ok", "state": state}, follow_redirects=False)
    assert "git=error" in replay.headers["location"]  # état consommé : usage unique


def test_connection_is_per_user(api, github):
    owner = register(api(), "owner@example.com")
    _connect(owner)
    token = owner.post("/api/org/invitations", json={"email": "dev@example.com", "role": "member"}).json()["url"]
    member = register(api(), "dev@example.com", org_name=None, invitation_token=token.rsplit("/", 1)[1])
    assert member.get("/api/git/github/repos").status_code == 409  # le compte GitHub du propriétaire ne lui sert pas


def test_private_repo_scan_passes_token_out_of_band(api, github, monkeypatch):
    captured = {}

    def fake_clone(url, branch, dest, settings, auth_header=None):
        captured.update(url=url, branch=branch, auth_header=auth_header)
        dest.mkdir(parents=True)
        (dest / "app.py").write_text("import os\nos.system(cmd)\n", encoding="utf-8")

    monkeypatch.setattr(main, "clone_repository", fake_clone)
    client = register(api(), "jane.doe@example.com")
    _connect(client)
    scan = client.post("/api/scans/git", json={"provider": "github", "repo": "acme/portail-prive"}).json()
    github.executor.shutdown(wait=True)
    assert scan["project_name"] == "portail-prive" and scan["source_url"] == "https://github.com/acme/portail-prive.git@main"
    assert GH_TOKEN not in scan["source_url"]
    assert captured["branch"] == "main"
    assert base64.b64decode(captured["auth_header"].removeprefix("Basic ")).decode() == f"x-access-token:{GH_TOKEN}"
    done = client.get(f"/api/scans/{scan['id']}").json()
    assert done["status"] == "completed" and done["summary"]["total"] == 1


def test_disconnect(api, github):
    client = register(api(), "jane.doe@example.com")
    _connect(client)
    assert client.delete("/api/git/github").status_code == 200
    assert client.get("/api/git/github/repos").status_code == 409


def test_tokenbox_binds_ciphertext_to_owner():
    sealed = encrypt("secret-de-test", TOKEN_KEY, "org1:user1:github")
    assert decrypt(sealed, TOKEN_KEY, "org1:user1:github") == "secret-de-test"
    with pytest.raises(InvalidTag):
        decrypt(sealed, TOKEN_KEY, "org2:user1:github")  # chiffré déplacé vers un autre propriétaire : refusé
