"""Couche 2 — détection de secrets.

Règle absolue : la valeur d'un secret n'est JAMAIS stockée, journalisée ni envoyée à l'IA.
On conserve uniquement le type, l'emplacement, une empreinte SHA-256 tronquée et un masque.
Le contenu des fichiers est caviardé avant toute autre utilisation (extraits, IA, rapports).
"""
import hashlib
import math
import re
from dataclasses import dataclass

from ..ingest import SourceFile
from ..models import Severity


@dataclass(frozen=True)
class SecretPattern:
    id: str
    label: str
    pattern: re.Pattern
    severity: Severity
    keep_prefix: int  # nombre de caractères de préfixe conservés dans le masque
    group: int = 0


SECRET_PATTERNS = [
    SecretPattern("SECRET-AWS", "Clé d'accès AWS", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), Severity.critical, 4),
    SecretPattern(
        "SECRET-STRIPE", "Clé secrète Stripe",
        re.compile(r"\b[sr]k_(live|test)_[0-9a-zA-Z]{16,}\b"), Severity.critical, 8,
    ),
    SecretPattern("SECRET-GITHUB", "Jeton GitHub", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), Severity.critical, 4),
    SecretPattern("SECRET-SLACK", "Jeton Slack", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), Severity.high, 5),
    SecretPattern("SECRET-GOOGLE", "Clé d'API Google", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), Severity.high, 4),
    SecretPattern(
        "SECRET-PRIVKEY", "Clé privée",
        re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"), Severity.critical, 0,
    ),
    SecretPattern(
        "SECRET-JWT", "Jeton JWT",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), Severity.high, 3,
    ),
    SecretPattern(
        "SECRET-GENERIC", "Mot de passe ou secret codé en dur",
        re.compile(
            r"(?i)[\w$]*(password|passwd|pwd|secret|api_?key|access_?token|auth_?token)[\w]*"
            r"\s*[:=]\s*[\"']([^\"'\s]{8,})[\"']"
        ),
        Severity.high, 0, group=2,
    ),
]

_PLACEHOLDERS = re.compile(r"(?i)^(changeme|password|secret|x{4,}|\*{4,}|your[_-]|<|\$\{|\{\{|%\(|process\.env|os\.environ)")


def fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:12]


def mask(value: str, keep_prefix: int) -> str:
    prefix = value[:keep_prefix] if keep_prefix and len(value) > keep_prefix + 4 else ""
    return f"{prefix}****"


def _entropy(value: str) -> float:
    counts = {c: value.count(c) for c in set(value)}
    return -sum(n / len(value) * math.log2(n / len(value)) for n in counts.values())


@dataclass
class SecretMatch:
    pattern: SecretPattern
    line: int
    start: int
    end: int
    fingerprint: str
    masked: str


def find_secrets(source: SourceFile) -> list[SecretMatch]:
    matches: list[SecretMatch] = []
    for idx, line in enumerate(source.content.split("\n")):
        taken: list[tuple[int, int]] = []
        for pat in SECRET_PATTERNS:
            for m in pat.pattern.finditer(line):
                start, end = m.span(pat.group)
                value = m.group(pat.group)
                if any(s < end and start < e for s, e in taken):
                    continue
                if pat.id == "SECRET-GENERIC" and (_PLACEHOLDERS.match(value) or _entropy(value) < 2.5):
                    continue
                if pat.id == "SECRET-PRIVKEY":
                    value = source.content  # empreinte du fichier entier, le marqueur n'est pas secret
                taken.append((start, end))
                matches.append(
                    SecretMatch(pat, idx + 1, start, end, fingerprint(value), mask(m.group(pat.group), pat.keep_prefix))
                )
    return matches


def redact(source: SourceFile, matches: list[SecretMatch]) -> SourceFile:
    """Renvoie une copie du fichier dont les valeurs secrètes sont remplacées par leur masque."""
    if not matches:
        return source
    lines = source.content.split("\n")
    by_line: dict[int, list[SecretMatch]] = {}
    for m in matches:
        by_line.setdefault(m.line, []).append(m)
    for line_no, items in by_line.items():
        line = lines[line_no - 1]
        for m in sorted(items, key=lambda x: x.start, reverse=True):
            if m.pattern.id == "SECRET-PRIVKEY":
                continue
            line = line[: m.start] + m.masked + line[m.end :]
        lines[line_no - 1] = line
    # Corps des clés privées : chaque ligne est masquée (le nombre de lignes est conservé)
    content = re.sub(
        r"(-----BEGIN [A-Z ]*PRIVATE KEY-----)([\s\S]*?)(-----END [A-Z ]*PRIVATE KEY-----)",
        lambda m: m.group(1) + re.sub(r"[^\n]+", "****", m.group(2)) + m.group(3),
        "\n".join(lines),
    )
    return SourceFile(path=source.path, language=source.language, content=content)
