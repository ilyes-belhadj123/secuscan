"""Couche 1 — analyse statique par règles.

Interface d'adaptateur : `analyze(file) -> list[RawFinding]`. Le moteur maison peut être
remplacé ou complété par un moteur SAST open source (sortie SARIF) sans toucher au pipeline.
"""
import re
from dataclasses import dataclass

from ..ingest import SourceFile
from ..models import Severity
from .iac import IAC_LANGUAGES, file_findings
from .rules import RULES, RULES_BY_ID, Rule
from .taint import describe, find_flows

_COMMENT_LINE = re.compile(r"^\s*(#|//|/\*|\*)")


@dataclass
class RawFinding:
    kind: str
    rule_id: str
    title: str
    message: str
    cwe: str | None
    severity: Severity
    file: str
    language: str
    start_line: int
    end_line: int
    extra: dict | None = None


def analyze_file(source: SourceFile, rules: list[Rule] = RULES) -> list[RawFinding]:
    lines = source.content.split("\n")
    applicable = [
        r for r in rules
        if source.language in r.languages and not (r.file_excludes and r.file_excludes.search(source.content))
    ]
    results: list[RawFinding] = []
    for idx, line in enumerate(lines):
        if not line.strip() or _COMMENT_LINE.match(line):
            continue
        for rule in applicable:
            if not rule.pattern.search(line):
                continue
            if rule.line_excludes and rule.line_excludes.search(line):
                continue
            if rule.context_requires:
                # La ligne et les 3 précédentes (typiquement la signature de la fonction)
                window = "\n".join(lines[max(0, idx - 3) : idx + 1])
                if not rule.context_requires.search(window):
                    continue
            results.append(
                RawFinding(
                    kind="sast",
                    rule_id=rule.id,
                    title=rule.title,
                    message=rule.description,
                    cwe=rule.cwe,
                    severity=rule.severity,
                    file=source.path,
                    language=source.language,
                    start_line=idx + 1,
                    end_line=idx + 1,
                )
            )
    if rules is RULES:
        results += _flows(source, results)
        if source.language in IAC_LANGUAGES:
            results += _file_level(source, results)
    return results


def _file_level(source: SourceFile, line_findings: list[RawFinding]) -> list[RawFinding]:
    """Contrôles d'infrastructure qui portent sur le fichier entier (iac.py)."""
    flagged = {(f.start_line, f.cwe) for f in line_findings}
    return [
        RawFinding(kind="sast", rule_id=rule.id, title=rule.title, message=rule.description, cwe=rule.cwe,
                   severity=rule.severity, file=source.path, language=source.language, start_line=line, end_line=line)
        for rule, line in file_findings(source) if (line, rule.cwe) not in flagged
    ]


def _flows(source: SourceFile, line_findings: list[RawFinding]) -> list[RawFinding]:
    """Alertes de flux (taint.py), sauf sur une ligne déjà signalée pour la même faille."""
    flagged = {(f.start_line, f.cwe) for f in line_findings}
    out = []
    for flow in find_flows(source):
        rule = RULES_BY_ID[flow.rule_id]
        # Déjà signalée sur la ligne du puits, ou sur celle où la valeur a été construite (même faille)
        if (flow.line, rule.cwe) in flagged or (flow.assigned_line, rule.cwe) in flagged:
            continue
        out.append(RawFinding(
            kind="sast", rule_id=rule.id, title=rule.title, message=describe(flow), cwe=rule.cwe,
            severity=rule.severity, file=source.path, language=source.language,
            start_line=flow.line, end_line=flow.line,
        ))
    return out
