"""Secrets écrits sans guillemets dans les fichiers de configuration.

`application.properties`, `.ini`, `.env`, `.npmrc` écrivent `cle=valeur` : le motif générique (valeur
entre guillemets, pensé pour le code) ne les voit pas. Ce motif ne s'applique qu'aux fichiers de
configuration (ingest.CONFIG_LANGUAGE), ligne par ligne, et laisse de côté les références à une
variable d'environnement ou à un coffre (`${DB_PASSWORD}`), les valeurs factices et les valeurs trop
simples pour être un secret.
"""
import re

from ..ingest import SourceFile
from ..models import Severity
from . import secrets

PATTERN = secrets.SecretPattern(
    "SECRET-CONFIG", "Mot de passe ou secret dans un fichier de configuration",
    re.compile(
        r"(?im)^\s*(?:export\s+)?[\w.\-/:]*?(password|passwd|pwd|secret|api[_-]?key|access[_-]?key|private[_-]?key"
        r"|auth[_-]?token|_authtoken|token|credentials?)[\w.\-]*\s*[=:]\s*([^\s\"'#;][^\s#;]{7,})\s*$"
    ),
    Severity.high, 0, group=2,
)
_NOT_SECRET = re.compile(r"(?i)^(true|false|null|none|yes|no|\d+|[\w.-]+\.(?:pem|key|crt|p12|jks)|/\S*)$")
# Libellés traduits (« password=Passwort ») : fichiers de messages, ou valeur faite de lettres seulement
_TRANSLATIONS = re.compile(r"(?i)(^|/)(i18n|l10n|locales?|lang|translations?)/|(^|/)messages[\w-]*\.properties$"
                           r"|_[a-z]{2}(_[A-Z]{2})?\.properties$")
_WORD = re.compile(r"^[^\W\d_]+$")


def find_config_secrets(source: SourceFile, existing: list) -> list:
    """Correspondances au même format que secrets.find_secrets, hors de celles déjà trouvées."""
    if _TRANSLATIONS.search(source.path):
        return []
    taken = {(m.line, m.start, m.end) for m in existing}
    matches = []
    for idx, line in enumerate(source.content.split("\n"), start=1):
        for m in PATTERN.pattern.finditer(line):
            value = m.group(PATTERN.group)
            start, end = m.span(PATTERN.group)
            if any(ln == idx and s < end and start < e for ln, s, e in taken):
                continue
            if (secrets._PLACEHOLDERS.match(value) or _NOT_SECRET.match(value) or _WORD.match(value)
                    or secrets._entropy(value) < 2.5):
                continue
            matches.append(secrets.SecretMatch(PATTERN, idx, start, end, secrets.fingerprint(value),
                                               secrets.mask(value, PATTERN.keep_prefix)))
    return matches
