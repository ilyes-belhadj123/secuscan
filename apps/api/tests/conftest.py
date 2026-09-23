import pytest

from secuscan.config import Settings
from secuscan.pipeline import ScanService
from secuscan.storage import Storage


@pytest.fixture
def settings(tmp_path) -> Settings:
    # Aucun appel réseau pendant les tests : pas de clé IA, OSV hors ligne
    return Settings(
        _env_file=None, openrouter_api_key="", secuscan_data_dir=tmp_path / "data", secuscan_offline=True
    )


@pytest.fixture
def service(settings) -> ScanService:
    return ScanService(settings, Storage(settings.data_dir / "test.db"))
