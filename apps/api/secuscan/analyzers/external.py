"""SS-5 — moteurs SAST externes, en complément des règles maison.

- Bandit (Python, licence Apache 2.0) : exécuté en sous-processus, sortie JSON.
- Adaptateur SARIF générique : importe les résultats de tout moteur produisant du SARIF 2.1.0
  (ex. Opengrep avec des règles propres à l'éditeur ; voir docs/moteurs-sast.md pour les licences).

Les résultats externes sont normalisés en RawFinding. Une ligne déjà signalée par une règle maison
n'est pas dupliquée : l'alerte maison, plus riche (explication, correctif), est conservée.
"""
import json
import logging
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from ..models import Severity
from .sast import RawFinding

log = logging.getLogger(__name__)
ENGINE_TIMEOUT_SECONDS = 300

_LEVELS = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
# CWE à fort impact : sévérité critique quelle que soit l'échelle du moteur
_CRITICAL_CWES = {"CWE-78", "CWE-89", "CWE-94", "CWE-95", "CWE-98", "CWE-502", "CWE-611", "CWE-1336"}
# Bandit classe certains tests de façon approximative : on retient le CWE le plus précis
_BANDIT_CWE_OVERRIDES = {"B307": "CWE-95", "B506": "CWE-502", "B324": "CWE-328", "B105": "CWE-798",
                         "B106": "CWE-798", "B107": "CWE-798", "B303": "CWE-328"}
_BANDIT_TITLES = {
    "B102": "Exécution de code dynamique", "B307": "Exécution de code dynamique",
    "B301": "Désérialisation non sécurisée", "B506": "Chargement YAML non sécurisé",
    "B602": "Injection de commande système", "B605": "Injection de commande système",
    "B608": "Injection SQL", "B501": "Vérification TLS désactivée", "B324": "Algorithme de hachage faible",
    "B201": "Mode debug activé", "B701": "Échappement automatique des templates désactivé",
    "B105": "Mot de passe codé en dur", "B310": "Ouverture d'URL non contrôlée", "B314": "Parseur XML vulnérable",
}


def _severity(cwe: str | None, level: Severity) -> Severity:
    return Severity.critical if cwe in _CRITICAL_CWES and level in (Severity.high, Severity.medium) else level


# ---------------------------------------------------------------------- Bandit
def bandit_available() -> bool:
    try:
        import bandit  # noqa: F401
    except ImportError:
        return False
    return True


def parse_bandit(report: dict, root: Path, min_level: str = "MEDIUM") -> list[RawFinding]:
    threshold = _LEVELS[min_level]
    findings = []
    for r in report.get("results", []):
        test_id = r.get("test_id", "")
        # B4xx : simples imports de modules « sensibles », trop bruyants pour être des alertes
        if test_id.startswith("B4") or _LEVELS.get(r.get("issue_severity"), 0) < threshold \
                or _LEVELS.get(r.get("issue_confidence"), 0) < threshold:
            continue
        try:
            rel = Path(r["filename"]).resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            continue
        cwe_id = (r.get("issue_cwe") or {}).get("id")
        cwe = _BANDIT_CWE_OVERRIDES.get(test_id) or (f"CWE-{cwe_id}" if cwe_id else None)
        level = {"HIGH": Severity.high, "MEDIUM": Severity.medium}.get(r["issue_severity"], Severity.low)
        lines = r.get("line_range") or [r["line_number"]]
        findings.append(RawFinding(
            kind="sast", rule_id=f"BANDIT-{test_id}",
            title=_BANDIT_TITLES.get(test_id, r.get("test_name", test_id).replace("_", " ").capitalize()),
            message=f"{r.get('issue_text', '').strip()} (Bandit {test_id})",
            cwe=cwe, severity=_severity(cwe, level), file=rel, language="python",
            start_line=int(r["line_number"]), end_line=int(max(lines)),
        ))
    return findings


def run_bandit(root: Path, files: list[str]) -> list[RawFinding]:
    """Bandit sur les fichiers Python collectés (exclusions et dossiers ignorés déjà appliqués)."""
    if not files or not bandit_available():
        return []
    with tempfile.TemporaryDirectory(prefix="secuscan-bandit-") as tmp:
        out = Path(tmp) / "bandit.json"
        cmd = [sys.executable, "-m", "bandit", "-q", "-f", "json", "-o", str(out), "--exit-zero",
               *[str(root / f) for f in files]]
        try:
            subprocess.run(cmd, capture_output=True, timeout=ENGINE_TIMEOUT_SECONDS, check=False)
            report = json.loads(out.read_text(encoding="utf-8")) if out.exists() else {}
        except (subprocess.TimeoutExpired, OSError, json.JSONDecodeError) as exc:
            log.warning("Bandit indisponible : %s", exc)
            return []
    return parse_bandit(report, root)


# ---------------------------------------------------------------------- SARIF générique
_SARIF_LEVEL = {"error": Severity.high, "warning": Severity.medium, "note": Severity.low, "none": Severity.low}
_CWE_TAG = re.compile(r"CWE-?(\d+)", re.I)


def _sarif_severity(rule: dict, result: dict) -> Severity:
    score = (rule.get("properties") or {}).get("security-severity")
    try:
        value = float(score)
        return (Severity.critical if value >= 9 else Severity.high if value >= 7
                else Severity.medium if value >= 4 else Severity.low)
    except (TypeError, ValueError):
        level = result.get("level") or (rule.get("defaultConfiguration") or {}).get("level") or "warning"
        return _SARIF_LEVEL.get(level, Severity.medium)


def parse_sarif(sarif: dict, known_files: dict[str, str], engine: str = "SARIF") -> list[RawFinding]:
    """`known_files` : chemin relatif → langage des fichiers collectés (les autres résultats sont ignorés)."""
    findings = []
    for run in sarif.get("runs", []):
        driver = (run.get("tool") or {}).get("driver") or {}
        name = driver.get("name") or engine
        rules = {r.get("id"): r for r in driver.get("rules", [])}
        for result in run.get("results", []):
            rule_id = result.get("ruleId") or "inconnu"
            rule = rules.get(rule_id, {})
            try:
                loc = result["locations"][0]["physicalLocation"]
                uri = loc["artifactLocation"]["uri"]
                region = loc.get("region") or {}
            except (KeyError, IndexError, TypeError):
                continue
            rel = re.sub(r"^(file://)?(\./)?", "", uri).replace("\\", "/")
            if rel not in known_files:
                continue
            tags = " ".join((rule.get("properties") or {}).get("tags", []))
            match = _CWE_TAG.search(tags)
            cwe = f"CWE-{match.group(1)}" if match else None
            start = int(region.get("startLine", 1))
            title = (rule.get("shortDescription") or {}).get("text") or rule.get("name") or rule_id
            findings.append(RawFinding(
                kind="sast", rule_id=f"{name.upper()}-{rule_id}"[:80], title=title[:120],
                message=((result.get("message") or {}).get("text") or title)[:500],
                cwe=cwe, severity=_severity(cwe, _sarif_severity(rule, result)), file=rel,
                language=known_files[rel], start_line=start, end_line=int(region.get("endLine", start)),
            ))
    return findings


def run_opengrep(root: Path, rules_dir: str, known_files: dict[str, str]) -> list[RawFinding]:
    """Opengrep (moteur LGPL 2.1) avec les règles de l'éditeur — jamais les règles Semgrep / Opengrep."""
    binary = shutil.which("opengrep")
    if not (binary and rules_dir and Path(rules_dir).is_dir()):
        return []
    with tempfile.TemporaryDirectory(prefix="secuscan-opengrep-") as tmp:
        out = Path(tmp) / "opengrep.sarif"
        cmd = [binary, "scan", "--config", rules_dir, "--sarif", "--output", str(out), "--quiet", str(root)]
        try:
            subprocess.run(cmd, capture_output=True, timeout=ENGINE_TIMEOUT_SECONDS, check=False, cwd=root)
            sarif = json.loads(out.read_text(encoding="utf-8")) if out.exists() else {}
        except (subprocess.TimeoutExpired, OSError, json.JSONDecodeError) as exc:
            log.warning("Opengrep indisponible : %s", exc)
            return []
    return parse_sarif(sarif, known_files, engine="Opengrep")
