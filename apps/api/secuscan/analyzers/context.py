"""Extraction du contexte de code autour d'une alerte (fonction englobante, en-tête du fichier)."""
import re
from dataclasses import dataclass

_FUNC_START = {
    "python": re.compile(r"^\s*(async\s+def|def|class)\s+\w+|^\s*@\w+"),
    "javascript": re.compile(
        r"^\s*(export\s+)?(async\s+)?function\b|^\s*(const|let|var)\s+\w+\s*=\s*(async\s*)?\(|"
        r"^\s*\w+\.(get|post|put|delete|patch|use)\(|^\s*(export\s+)?class\b"
    ),
    "php": re.compile(r"^\s*((public|private|protected|static)\s+)*function\b|^\s*//|^\s*\$\w+\s*=\s*\$_"),
    "java": re.compile(r"^\s*(public|private|protected)\s+[\w<>\[\], ]+\s+\w+\s*\([^;]*$"),
}
_FUNC_START["typescript"] = _FUNC_START["javascript"]

_IMPORT = re.compile(r"^\s*(import\b|from\s+\S+\s+import\b|const\s+.*=\s*require\(|use\s+[\w\\]+;|package\b)")

_CLOSING_ONLY = re.compile(r"^\s*[}\])]+[;,)]*\s*$")


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip())


MAX_BEFORE = 40
MAX_AFTER = 30
MAX_LINES = 150


@dataclass
class Excerpt:
    start_line: int  # 1-indexé
    end_line: int
    code: str

    def numbered(self) -> str:
        return "\n".join(
            f"{self.start_line + i:>4} | {line}" for i, line in enumerate(self.code.split("\n"))
        )


def _is_start(language: str, line: str) -> bool:
    pattern = _FUNC_START.get(language)
    return bool(pattern and pattern.search(line))


def enclosing_excerpt(lines: list[str], language: str, start: int, end: int) -> Excerpt:
    """Renvoie la fonction (ou le bloc) qui contient les lignes start..end (1-indexées)."""
    n = len(lines)
    top = start
    for i in range(start, max(0, start - MAX_BEFORE), -1):
        if _is_start(language, lines[i - 1]):
            top = i
            # Remonter les décorateurs Python / commentaires collés
            while top > 1 and (lines[top - 2].lstrip().startswith(("@", "#", "//", "*", "/*"))):
                top -= 1
            break
    else:
        top = max(1, start - 8)

    bottom = end
    # Python : si l'extrait démarre en colonne 0 (fonction de premier niveau), la première
    # instruction non indentée qui suit marque la fin du bloc.
    block_at_col0 = language == "python" and not lines[top - 1][:1].isspace()
    for i in range(end + 1, min(n, end + MAX_AFTER) + 1):
        line = lines[i - 1]
        dedented = block_at_col0 and line[:1] not in ("", " ", "\t", "#", ")", "]", "}")
        if (_is_start(language, line) or dedented) and i > end + 1:
            bottom = i - 1
            break
        bottom = i
    # Retirer les lignes vides et les fermetures des blocs parents (ex. « } » de la classe qui
    # suit la dernière méthode) : moins indentées que le début de l'extrait, elles n'en font pas partie
    base_indent = _indent(lines[top - 1])
    while bottom > end and (
        not lines[bottom - 1].strip()
        or (_CLOSING_ONLY.match(lines[bottom - 1]) and _indent(lines[bottom - 1]) < base_indent)
    ):
        bottom -= 1

    if bottom - top + 1 > MAX_LINES:
        top = max(1, start - 20)
        bottom = min(n, end + 20)
    return Excerpt(top, bottom, "\n".join(lines[top - 1 : bottom]))


# Constantes de niveau module : l'IA doit voir qu'une valeur concaténée est fixe (ex. TABLE = "users")
_CONSTANT = re.compile(
    r"^([A-Z][A-Z0-9_]*\s*=|(export\s+)?const\s+[A-Z][A-Z0-9_]*\s*=|define\(|const\s+[A-Z][A-Z0-9_]*\s*=|"
    r"\s*(private|public|protected)?\s*static\s+final\s)"
)


def file_header(lines: list[str], limit: int = 40) -> str:
    """Imports et constantes de niveau module, utiles à l'IA pour juger d'où viennent les valeurs."""
    header = [line for line in lines[:200] if _IMPORT.match(line) or _CONSTANT.match(line)]
    return "\n".join(line[:200] for line in header[:limit])
