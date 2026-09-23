"""Couche 1 — analyse statique par règles.

Interface d'adaptateur : `analyze(file) -> list[RawFinding]`. Le moteur maison peut être
remplacé ou complété par un moteur SAST open source (sortie SARIF) sans toucher au pipeline.
"""
import re
from dataclasses import dataclass

from ..ingest import SourceFile
from ..models import Severity
from .rules import RULES, Rule

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
            if rule.context_requires:
                window = "\n".join(lines[max(0, idx - 3) : idx + 4])
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
    return results
