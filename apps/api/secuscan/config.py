from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

API_ROOT = Path(__file__).resolve().parent.parent
REPO_ROOT = API_ROOT.parent.parent
DEMO_PROJECT_DIR = REPO_ROOT / "demo" / "acme-shop"


# Budget IA par analyse et par offre : (appels max, jetons max)
PLAN_AI_BUDGETS = {
    "free": (40, 120_000),
    "pro": (150, 500_000),
    "business": (500, 2_000_000),
}


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
    # Revue logique IA : fichiers de code analysés en entier (coût maîtrisé)
    secuscan_logic_max_files: int = 40
    secuscan_logic_max_lines: int = 400

    # Maîtrise des coûts IA (SS-12)
    secuscan_plan: str = "pro"
    # Part maximale du budget d'appels consacrée à la revue logique des fichiers
    secuscan_logic_budget_share: float = 0.25
    # Dépendances expliquées par l'IA (les plus graves) ; les autres : explication locale depuis OSV
    secuscan_ai_max_dependency_reviews: int = 10
    # Tarifs en $ par million de jetons (Claude Sonnet 5 : 2 $ en entrée, 10 $ en sortie)
    secuscan_ai_price_input_per_mtok: float = 2.0
    secuscan_ai_price_output_per_mtok: float = 10.0

    @property
    def ai_budget(self) -> tuple[int, int]:
        """(appels max, jetons max) par analyse selon l'offre."""
        return PLAN_AI_BUDGETS.get(self.secuscan_plan, PLAN_AI_BUDGETS["pro"])

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
