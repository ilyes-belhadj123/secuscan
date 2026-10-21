"""Mise en ligne : interface servie par l'API, en-têtes de sécurité, vérification de la configuration."""
import pytest
from fastapi.testclient import TestClient

from secuscan.config import Settings
from secuscan.main import app


@pytest.fixture
def web(api, service, tmp_path):
    dist = tmp_path / "dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text("<!doctype html><div id=root></div>", encoding="utf-8")
    (dist / "assets" / "index-abc123.js").write_text("console.log(1)", encoding="utf-8")
    (tmp_path / "secret.txt").write_text("hors du dossier dist", encoding="utf-8")
    service.settings.secuscan_web_dist = dist
    return api()


def test_spa_routes_and_assets(web):
    for path in ("/", "/scans/abc", "/parametres"):
        resp = web.get(path)
        assert resp.status_code == 200 and "id=root" in resp.text and resp.headers["cache-control"] == "no-cache"
    asset = web.get("/assets/index-abc123.js")
    assert asset.status_code == 200 and "immutable" in asset.headers["cache-control"]


def test_api_paths_never_fall_back_to_index(web):
    resp = web.get("/api/inconnue")
    assert resp.status_code == 404 and resp.headers["content-type"].startswith("application/json")


@pytest.mark.parametrize("path", ["/../secret.txt", "/%2e%2e/secret.txt", "/assets/..%2f..%2fsecret.txt"])
def test_no_path_traversal(web, path):
    assert "hors du dossier" not in web.get(path).text


def test_security_headers(web, service):
    resp = web.get("/")
    assert resp.headers["x-frame-options"] == "DENY" and resp.headers["x-content-type-options"] == "nosniff"
    assert "script-src 'self'" in resp.headers["content-security-policy"]
    assert "strict-transport-security" not in resp.headers  # HTTP local : pas de HSTS
    service.settings.secuscan_cookie_secure = True
    assert "max-age" in web.get("/api/health").headers["strict-transport-security"]


def test_public_url_origin_is_allowed(api, service):
    service.settings.secuscan_public_url = "https://secuscan.example.com"
    client = api()
    assert client.post("/api/auth/logout", headers={"Origin": "https://secuscan.example.com"}).status_code == 200
    assert client.post("/api/auth/logout", headers={"Origin": "https://evil.example.com"}).status_code == 403


def test_production_problems(tmp_path):
    dist = tmp_path / "dist"
    dist.mkdir()
    settings = Settings(_env_file=None, secuscan_web_dist=dist, secuscan_github_client_id="placeholder-id")
    problems = " ".join(settings.production_problems())
    for expected in ("https://", "SECUSCAN_COOKIE_SECURE", "SECUSCAN_TOKEN_KEY", "npm run build",
                     "SECUSCAN_OPERATOR_EMAILS"):
        assert expected in problems
    (dist / "index.html").write_text("ok")
    ok = Settings(_env_file=None, secuscan_web_dist=dist, secuscan_public_url="https://secuscan.example.com",
                  secuscan_cookie_secure=True, secuscan_operator_emails=["ops@example.com"])
    assert ok.production_problems() == []


def test_production_refuses_unsafe_start(api, service):
    service.settings.secuscan_production = True
    with pytest.raises(RuntimeError, match="Configuration de production incomplète"):
        with TestClient(app):
            pass


def test_settings_page_file_is_read_at_startup(tmp_path, monkeypatch):
    from secuscan import config
    env_file = tmp_path / "secuscan.env"
    env_file.write_text("OPENROUTER_MODEL=anthropic/claude-haiku-5.5\n", encoding="utf-8")
    monkeypatch.setenv("SECUSCAN_ENV_FILE", str(env_file))
    monkeypatch.delenv("OPENROUTER_MODEL", raising=False)
    monkeypatch.setattr(config, "DEFAULT_ENV_FILES", ())
    config.get_settings.cache_clear()
    try:
        assert config.get_settings().openrouter_model == "anthropic/claude-haiku-5.5"
    finally:
        config.get_settings.cache_clear()
