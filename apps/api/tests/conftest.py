import pytest
from fastapi.testclient import TestClient

from secuscan import accounts, deps
from secuscan.config import Settings
from secuscan.main import app
from secuscan.pipeline import ScanService
from secuscan.storage import Storage

PASSWORD = "Test-Passw0rd-42"


@pytest.fixture
def settings(tmp_path) -> Settings:
    # Aucun appel réseau pendant les tests : pas de clé IA, OSV hors ligne
    return Settings(
        _env_file=None, openrouter_api_key="", secuscan_data_dir=tmp_path / "data", secuscan_offline=True
    )


@pytest.fixture
def service(settings) -> ScanService:
    return ScanService(settings, Storage(settings.data_dir / "test.db"))


@pytest.fixture
def api(service):
    """Fabrique de clients HTTP : chaque client a ses propres cookies (un utilisateur = un navigateur)."""
    deps.set_service(service)
    accounts.login_limiter._failures.clear()
    accounts.reset_limiter._failures.clear()
    yield lambda: TestClient(app)
    deps.set_service(None)


def register(client: TestClient, email: str, org_name: str | None = "Acme Corp", **extra) -> TestClient:
    body = {"name": email.split("@")[0], "email": email, "password": PASSWORD, "org_name": org_name, **extra}
    resp = client.post("/api/auth/register", json=body)
    assert resp.status_code == 201, resp.text
    return client
