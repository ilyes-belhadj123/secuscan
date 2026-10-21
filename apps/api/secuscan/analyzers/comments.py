"""Blocs de commentaires masqués avant l'analyse par règles et par flux.

Le code mis en commentaire (`/* ancienne version … */`, une correction proposée en commentaire) n'est
pas exécuté : il ne doit produire aucune alerte. Les caractères des commentaires sont remplacés par
des espaces, les retours à la ligne conservés : les numéros de ligne et de colonne ne bougent pas.
Les chaînes de caractères sont respectées (« "/*" » dans un motif de fichiers n'ouvre rien).
"""
from ..ingest import SourceFile

C_LIKE = {"javascript", "typescript", "java", "php", "csharp", "go"}
_QUOTES = {"javascript": "\"'`", "typescript": "\"'`", "go": "\"'`", "php": "\"'", "java": "\"'", "csharp": "\"'"}


def _blank(text: str) -> str:
    return "".join(c if c == "\n" else " " for c in text)


def mask_block_comments(content: str, language: str) -> str:
    if language not in C_LIKE or "/*" not in content:
        return content
    quotes = _QUOTES[language]
    out: list[str] = []
    i, n, start = 0, len(content), 0
    while i < n:
        c = content[i]
        if c in quotes:  # chaîne : jusqu'au guillemet fermant (non échappé) ou fin de ligne
            j = i + 1
            while j < n and content[j] != c and (content[j] != "\n" or c == "`"):
                j += 2 if content[j] == "\\" else 1
            i = j + 1
        elif content.startswith("//", i):  # commentaire de ligne : laissé tel quel
            j = content.find("\n", i)
            i = n if j < 0 else j
        elif content.startswith("/*", i) and not (i and content[i - 1] == "\\"):  # pas « /\/*/ » (regex)
            j = content.find("*/", i + 2)
            if j < 0:  # jamais refermé : probablement pas un commentaire, rien n'est masqué
                i += 2
                continue
            out += [content[start:i], _blank(content[i:j + 2])]
            i = start = j + 2
        else:
            i += 1
    out.append(content[start:])
    return "".join(out)


def without_block_comments(source: SourceFile) -> SourceFile:
    masked = mask_block_comments(source.content, source.language)
    return source if masked is source.content else SourceFile(source.path, source.language, masked)
