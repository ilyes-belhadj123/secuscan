from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field


def now_iso() -> str:
    return datetime.now(UTC).isoformat()


class Severity(StrEnum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"


SEVERITY_ORDER = {Severity.critical: 0, Severity.high: 1, Severity.medium: 2, Severity.low: 3}

# "ai" : faille logique détectée par la revue IA d'un fichier (aucune règle ne la couvre)
FindingKind = Literal["sast", "ai", "secret", "dependency"]
FindingStatus = Literal["open", "dismissed", "false_positive"]
ScanStatus = Literal["queued", "running", "completed", "failed"]


class Explanation(BaseModel):
    definition: str
    attack_scenario: str
    business_impact: str
    difficulty: str
    references: list[str] = []


class FixSuggestion(BaseModel):
    original_code: str
    patched_code: str
    diff: str
    explanation: str
    best_practices: list[str] = []
    syntax_valid: bool | None = None


class AIReview(BaseModel):
    verdict: Literal["true_positive", "false_positive", "uncertain"]
    confidence: float
    reason: str
    explanation: Explanation | None = None
    fix: FixSuggestion | None = None
    model: str
    cached: bool = False
    filtered: bool = False
    # "ai" : produit par le modèle ; "osv" : généré localement depuis la base de vulnérabilités
    generated_by: Literal["ai", "osv"] = "ai"


class Advisory(BaseModel):
    id: str
    aliases: list[str] = []
    summary: str = ""
    severity: Severity
    fixed_version: str | None = None
    url: str = ""


class DependencyInfo(BaseModel):
    ecosystem: str
    package: str
    version: str
    manifest: str
    advisories: list[Advisory] = []
    fixed_version: str | None = None


class SecretInfo(BaseModel):
    secret_type: str
    masked: str
    fingerprint: str


class Finding(BaseModel):
    id: str
    scan_id: str
    kind: FindingKind
    rule_id: str
    title: str
    message: str
    fix_hint: str | None = None
    language: str
    file: str
    start_line: int
    end_line: int
    # Extrait de code affichable (secrets masqués) et sa position dans le fichier
    snippet: str
    snippet_start_line: int
    cwe: str | None = None
    owasp: str | None = None
    raw_severity: Severity
    severity: Severity
    fingerprint: str
    status: FindingStatus = "open"
    dismiss_reason: str | None = None
    dismiss_justification: str | None = None
    ai: AIReview | None = None
    ai_error: str | None = None
    dependency: DependencyInfo | None = None
    secret: SecretInfo | None = None


class ScanSummary(BaseModel):
    total: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_kind: dict[str, int] = Field(default_factory=dict)
    by_owasp: dict[str, int] = Field(default_factory=dict)
    false_positives: int = 0
    dismissed: int = 0
    files_scanned: int = 0
    lines_scanned: int = 0
    languages: dict[str, int] = Field(default_factory=dict)
    ai_calls: int = 0
    ai_cache_hits: int = 0
    ai_tokens: int = 0
    ai_errors: int = 0
    ai_cost_usd: float = 0.0
    ai_budget_calls: int = 0
    ai_budget_refused: int = 0
    plan: str = ""
    # Limites de l'analyse à signaler à l'utilisateur (ex. base de vulnérabilités injoignable)
    warnings: list[str] = Field(default_factory=list)
    duration_seconds: float = 0.0


class Scan(BaseModel):
    id: str
    project_name: str
    # Organisation propriétaire (vide : outils internes, invisible des utilisateurs)
    org_id: str | None = None
    created_by: str | None = None
    # Offre de l'organisation au lancement (fixe le budget IA de l'analyse)
    plan: str | None = None
    source: Literal["upload", "snippet", "demo", "git"]
    source_url: str | None = None
    status: ScanStatus = "queued"
    stage: str = "En attente"
    progress: float = 0.0
    error: str | None = None
    created_at: str = Field(default_factory=now_iso)
    completed_at: str | None = None
    score: int | None = None
    summary: ScanSummary = Field(default_factory=ScanSummary)
    ai_enabled: bool = False
    previous_scan_id: str | None = None
    new_findings: int | None = None
    fixed_findings: int | None = None


class SnippetRequest(BaseModel):
    project_name: str = Field(default="Extrait de code", max_length=120)
    filename: str = Field(max_length=200)
    code: str = Field(max_length=500_000)


class GitRequest(BaseModel):
    url: str = Field(max_length=300)
    branch: str | None = Field(default=None, max_length=100)
    project_name: str | None = Field(default=None, max_length=120)


class DismissRequest(BaseModel):
    reason: Literal["false_positive", "accepted_risk", "not_applicable"]
    justification: str = Field(min_length=10, max_length=2000)
