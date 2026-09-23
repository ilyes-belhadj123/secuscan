"""Export SARIF 2.1.0 : format standard lu par GitHub Code Scanning, GitLab, Azure DevOps…"""
from .models import Finding, Severity

TOOL_VERSION = "0.2.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

# « security-severity » (0-10) : GitHub en déduit critique / élevée / moyenne / faible
_SECURITY_SEVERITY = {Severity.critical: "9.5", Severity.high: "8.0", Severity.medium: "5.5", Severity.low: "3.0"}
_LEVEL = {Severity.critical: "error", Severity.high: "error", Severity.medium: "warning", Severity.low: "note"}


def _rule(f: Finding) -> dict:
    tags = ["security"] + [t for t in (f.cwe, f.owasp) if t]
    rule = {
        "id": f.rule_id,
        "name": f.title,
        "shortDescription": {"text": f.title},
        "fullDescription": {"text": f.message},
        "help": {"text": f.fix_hint or f.message},
        "defaultConfiguration": {"level": _LEVEL[f.raw_severity]},
        "properties": {"tags": tags, "security-severity": _SECURITY_SEVERITY[f.raw_severity]},
    }
    if f.cwe:
        rule["helpUri"] = f"https://cwe.mitre.org/data/definitions/{f.cwe.split('-')[1]}.html"
    return rule


def _result(f: Finding) -> dict:
    text = f.message
    if f.ai and f.ai.explanation and f.ai.explanation.definition:
        text = f"{f.title} : {f.ai.explanation.definition}"
    result = {
        "ruleId": f.rule_id,
        "level": _LEVEL[f.severity],
        "message": {"text": text},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": f.file},
                "region": {"startLine": f.start_line, "endLine": f.end_line},
            }
        }],
        # Empreinte stable : GitHub suit la même alerte d'une analyse à l'autre
        "partialFingerprints": {"secuscanFingerprint/v1": f.fingerprint},
        "properties": {"severity": f.severity.value, "kind": f.kind},
    }
    if f.ai and f.ai.fix and f.ai.fix.explanation:
        result["properties"]["fix"] = f.ai.fix.explanation
    return result


def build_sarif(findings: list[Finding]) -> dict:
    """Seules les alertes ouvertes sont exportées (faux positifs écartés et alertes ignorées exclus)."""
    open_findings = [f for f in findings if f.status == "open"]
    rules: dict[str, dict] = {}
    for f in open_findings:
        rules.setdefault(f.rule_id, _rule(f))
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "SecuScan", "version": TOOL_VERSION,
                "informationUri": "https://github.com/ilyes-belhadj123/secuscan",
                "rules": list(rules.values()),
            }},
            "results": [_result(f) for f in open_findings],
        }],
    }
