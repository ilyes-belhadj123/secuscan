"""Définition d'une règle statique, partagée par tous les fichiers de règles (sans import circulaire)."""
import re
from dataclasses import dataclass, field

from ..models import Severity

JS_LANGS = ("javascript", "typescript")


@dataclass(frozen=True)
class Rule:
    id: str
    languages: tuple[str, ...]
    pattern: re.Pattern
    title: str
    cwe: str
    severity: Severity
    description: str
    fix_hint: str
    # Motif devant apparaître dans les lignes voisines (±3) pour déclencher la règle
    context_requires: re.Pattern | None = None
    # Motif qui, s'il est présent dans le fichier, désactive la règle (mitigation déjà en place)
    file_excludes: re.Pattern | None = None
    # Motif qui, s'il est présent sur la ligne, désactive la règle (ex. valeur échappée)
    line_excludes: re.Pattern | None = None
    tags: tuple[str, ...] = field(default_factory=tuple)
