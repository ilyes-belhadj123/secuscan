"""Sévérité finale et score de sécurité du projet.

Règles (documentées pour les clients) :
- Sévérité initiale = sévérité de la règle (ou de l'advisory pour les dépendances).
- Verdict IA « faux positif » avec confiance >= 0,7 → alerte masquée (statut false_positive).
- Verdict IA « incertain » sur une alerte critique → rétrogradée en « élevée ».
- Fichier de test ou d'exemple (tests/, *_test.*, spec, fixtures) → rétrogradée d'un niveau.
- Score = 100 × e^(−pénalité / 150), pénalité = Σ poids des alertes ouvertes
  (critique 20, élevée 8, moyenne 3, faible 1). Note : A ≥ 90, B ≥ 75, C ≥ 50, D ≥ 25, E < 25.
"""
import math
import re

from .models import Finding, Severity

WEIGHTS = {Severity.critical: 20, Severity.high: 8, Severity.medium: 3, Severity.low: 1}
_LEVELS = [Severity.critical, Severity.high, Severity.medium, Severity.low]
_TEST_PATH = re.compile(r"(^|/)(tests?|__tests__|spec|fixtures|examples?)(/|$)|[._-](test|spec)\.\w+$", re.I)

FALSE_POSITIVE_CONFIDENCE = 0.7


def downgrade(severity: Severity) -> Severity:
    idx = _LEVELS.index(severity)
    return _LEVELS[min(idx + 1, len(_LEVELS) - 1)]


def apply_severity(finding: Finding) -> None:
    severity = finding.raw_severity
    if _TEST_PATH.search(finding.file):
        severity = downgrade(severity)
    ai = finding.ai
    # Seules les alertes de règles statiques peuvent être écartées par l'IA : un secret masqué
    # ou une version vulnérable reste un fait, quel que soit le contexte.
    if ai and finding.kind == "sast":
        if ai.verdict == "false_positive" and ai.confidence >= FALSE_POSITIVE_CONFIDENCE:
            if finding.status == "open":
                finding.status = "false_positive"
        elif ai.verdict == "uncertain" and severity == Severity.critical:
            severity = Severity.high
    finding.severity = severity


def project_score(findings: list[Finding]) -> int:
    penalty = sum(WEIGHTS[f.severity] for f in findings if f.status == "open")
    return round(100 * math.exp(-penalty / 150))


def grade(score: int) -> str:
    for threshold, letter in ((90, "A"), (75, "B"), (50, "C"), (25, "D")):
        if score >= threshold:
            return letter
    return "E"
