from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

API_ROOT = Path(__file__).resolve().parent.parent
REPO_ROOT = API_ROOT.parent.parent
DEMO_PROJECT_DIR = REPO_ROOT / "demo" / "acme-shop"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(REPO_ROOT / ".env", API_ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    openrouter_api_key: str = ""
    openrouter_model: str = "anthropic/claude-sonnet-5"
    openrouter_url: str = "https://openrouter.ai/api/v1/chat/completions"

    secuscan_data_dir: Path = API_ROOT / "data"
    secuscan_ai_concurrency: int = 6
    secuscan_offline: bool = False

    # Limites d'import
    max_upload_bytes: int = 100 * 1024 * 1024
    max_uncompressed_bytes: int = 500 * 1024 * 1024
    max_compression_ratio: int = 100
    max_files: int = 20_000
    max_file_bytes: int = 1024 * 1024

    @property
    def ai_enabled(self) -> bool:
        return bool(self.openrouter_api_key)

    @property
    def data_dir(self) -> Path:
        path = self.secuscan_data_dir
        if not path.is_absolute():
            path = API_ROOT / path
        path.mkdir(parents=True, exist_ok=True)
        return path


@lru_cache
def get_settings() -> Settings:
    return Settings()
