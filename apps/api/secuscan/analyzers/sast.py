"""Couche 1 — analyse statique par règles.

Interface d'adaptateur : `analyze(file) -> list[RawFinding]`. Le moteur maison peut être
remplacé ou complété par un moteur SAST open source (sortie SARIF) sans toucher au pipeline.
"""
import re
from dataclasses import dataclass

from ..ingest import SourceFile
from ..models import Severity
from .comments import without_block_comments
from .iac import IAC_LANGUAGES, file_findings
from .rules import RULES, RULES_BY_ID, Rule
from .taint import _ALLOWLIST, describe, find_flows

_COMMENT_LINE = re.compile(r"^\s*(#|//|/\*|\*)")

# PHP : règles qui signalent une variable dans une requête, une commande ou une inclusion. Si toutes
# les variables de l'appel ne reçoivent que des textes fixes dans le fichier (« $sql = "SHOW TABLES" »,
# « $page = 'low.php' » dans un switch) ou une valeur d'une liste blanche (« in_array($p, $ok, true) ?
# $p : 'home' »), aucune entrée extérieure arbitraire ne peut les atteindre.
_PHP_CONSTANT_AWARE = {"PHP-SQLI", "PHP-CMDI", "PHP-LFI"}
_PHP_VAR = re.compile(r"\$(\w+)")
_PHP_LITERAL = re.compile(r"\s*('(?:[^'\\]|\\.)*'|\"(?:[^\"\\$]|\\.)*\")\s*;", re.S)
_PHP_DYNAMIC_SCOPE = re.compile(r"\bextract\s*\(|\$\$|\bparse_str\s*\(")
_PHP_NOT_VARS = {"this", "GLOBALS"}
_PHP_CONNECTION_ARG = re.compile(r"\b(mysqli_query|pg_query|mysql_query)\s*\(\s*(\$\w+(\[[^\]]*\])?)\s*,")


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


def _php_safe_value(content: str, pos: int) -> bool:
    if _PHP_LITERAL.match(content, pos):
        return True
    end = content.find(";", pos)
    return end > 0 and bool(_ALLOWLIST.search(content[pos:end]))


def _indent(content: str, pos: int) -> float:
    """Indentation de l'instruction qui commence à `pos` (infinie si elle ne débute pas la ligne)."""
    before = content[content.rfind("\n", 0, pos) + 1:pos]
    return len(before) if not before.strip() else float("inf")


def _php_constant(name: str, content: str, use: int) -> bool:
    """Valeur fixe (ou d'une liste blanche) à l'endroit `use`, et jamais reçue d'ailleurs. On retient
    la dernière affectation de même niveau avant l'usage (« $q = "SELECT COUNT(*)…" » juste avant la
    requête), et toutes celles, plus imbriquées, qui la suivent (branches d'un if ou d'un switch)."""
    v = re.escape(name)
    received = (rf"(function\s*\w*\s*\([^)]*|\bas\s+(\$\w+\s*=>\s*)?&?|\bglobal\s+[^;]*|\blist\s*\([^)]*"
                rf"|\[[^\]=]*|&)\${v}\b")
    if re.search(received, content):
        return False
    before = [m for m in re.finditer(rf"\${v}\s*\.?=(?![=>])", content) if m.start() < use]
    line = content[use:].split("\n", 1)[0]
    level = len(line) - len(line.lstrip())
    same_level = [i for i, m in enumerate(before) if _indent(content, m.start()) <= level]
    reaching = before[same_level[-1]:] if same_level else before
    return bool(reaching) and all(_php_safe_value(content, m.end()) for m in reaching)


def _php_only_constants(line: str, rule: Rule, content: str, line_start: int) -> bool:
    start = rule.pattern.search(line).start()
    call = line[start:]
    connection = _PHP_CONNECTION_ARG.search(call)
    if connection:  # connexion à la base : premier argument, sans rapport avec la requête
        call = call[:connection.start(2)] + call[connection.end(2):]
    names = {n for n in _PHP_VAR.findall(call) if n not in _PHP_NOT_VARS and not n.startswith("_")}
    return bool(names) and all(_php_constant(n, content, line_start) for n in names)


def analyze_file(source: SourceFile, rules: list[Rule] = RULES) -> list[RawFinding]:
    source = without_block_comments(source)  # code mis en commentaire : jamais exécuté
    lines = source.content.split("\n")
    constant_aware = source.language == "php" and not _PHP_DYNAMIC_SCOPE.search(source.content)
    applicable = [
        r for r in rules
        if source.language in r.languages and not (r.file_excludes and r.file_excludes.search(source.content))
        and not (r.file_requires and not r.file_requires.search(source.content))
    ]
    results: list[RawFinding] = []
    offset = 0  # position du début de la ligne dans le fichier
    for idx, line in enumerate(lines):
        line_start, offset = offset, offset + len(line) + 1
        if not line.strip() or _COMMENT_LINE.match(line):
            continue
        for rule in applicable:
            if not rule.pattern.search(line):
                continue
            if rule.line_excludes and rule.line_excludes.search(line):
                continue
            if constant_aware and rule.id in _PHP_CONSTANT_AWARE and _php_only_constants(
                    line, rule, source.content, line_start):
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
