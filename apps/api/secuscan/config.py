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
    # Coupe l'IA même si une clé est configurée (tests, démonstrations sans coût)
    secuscan_ai_disabled: bool = False
    secuscan_offline: bool = False
    # Moteurs SAST externes (SS-5), en complément des règles maison : bandit, opengrep
    secuscan_external_engines: list[str] = ["bandit"]
    # Dossier de règles Opengrep propres à l'éditeur (jamais les règles Semgrep : licence)
    secuscan_opengrep_rules: str = ""

    # Revue logique IA : fichiers de code analysés en entier (coût maîtrisé)
    secuscan_logic_max_files: int = 40
    secuscan_logic_max_lines: int = 400

    # Comptes et sessions (SS-2)
    # Adresse publique de l'interface (liens d'invitation)
    secuscan_public_url: str = "http://127.0.0.1:5173"
    # Cookie de session réservé au HTTPS : à activer dès que l'application est servie en HTTPS
    secuscan_cookie_secure: bool = False
    # Envoi d'e-mails (invitations, réinitialisation) : vide = boîte d'envoi locale data/outbox
    secuscan_smtp_host: str = ""
    secuscan_smtp_port: int = 587
    secuscan_smtp_user: str = ""
    secuscan_smtp_password: str = ""
    secuscan_smtp_starttls: bool = True
    secuscan_smtp_from: str = "SecuScan <no-reply@example.com>"
    # Origines autorisées pour les requêtes qui modifient des données (protection CSRF)
    secuscan_allowed_origins: list[str] = ["http://127.0.0.1:5173", "http://localhost:5173"]

    # Connexion GitHub / GitLab (SS-17) : identifiants des applications OAuth et clé de chiffrement
    secuscan_github_client_id: str = ""
    secuscan_github_client_secret: str = ""
    secuscan_gitlab_client_id: str = ""
    secuscan_gitlab_client_secret: str = ""
    secuscan_gitlab_url: str = "https://gitlab.com"
    # Clé AES-256 (base64) qui chiffre les jetons d'accès stockés
    secuscan_token_key: str = ""

    # Offres (SS-20)
    # Offre de la toute première organisation (propriétaire de l'installation) ; les suivantes : free
    secuscan_first_org_plan: str = "business"
    # Tarifs indicatifs en € HT par membre et par mois (provisoires, à valider commercialement)
    secuscan_price_pro_eur: float = 29.0
    secuscan_price_business_eur: float = 79.0
    # Secret partagé avec le prestataire de paiement pour signer les webhooks (vide : webhook désactivé)
    secuscan_billing_webhook_secret: str = ""

    # Maîtrise des coûts IA (SS-12)
    # Offre par défaut des analyses sans organisation (outils internes : benchmark, préparation démo)
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
        """(appels max, jetons max) par analyse pour l'offre par défaut (outils internes)."""
        return self.ai_budget_for(self.secuscan_plan)

    @staticmethod
    def ai_budget_for(plan: str | None) -> tuple[int, int]:
        return PLAN_AI_BUDGETS.get(plan or "free", PLAN_AI_BUDGETS["free"])

    def price_per_member(self, plan: str) -> float:
        return {"pro": self.secuscan_price_pro_eur, "business": self.secuscan_price_business_eur}.get(plan, 0.0)

    # Limites d'import
    max_upload_bytes: int = 100 * 1024 * 1024
    max_uncompressed_bytes: int = 500 * 1024 * 1024
    max_compression_ratio: int = 100
    max_files: int = 20_000
    max_file_bytes: int = 1024 * 1024

    @property
    def ai_enabled(self) -> bool:
        return bool(self.openrouter_api_key) and not self.secuscan_ai_disabled

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
