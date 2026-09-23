"""Filtre de sortie : retire des explications toute charge offensive exploitable."""
import re

_OFFENSIVE = [
    re.compile(p, re.I)
    for p in (
        r"'\s*or\s+'?1'?\s*=\s*'?1",
        r"\bunion\s+(all\s+)?select\b",
        r";\s*drop\s+table\b",
        r"<\s*script\b",
        r"\bon(error|load)\s*=",
        r"javascript\s*:",
        r"\$\{\s*jndi\s*:",
        r"\brm\s+-rf\b",
        r"/etc/(passwd|shadow)",
        r"\.\./\.\./",
        r"\b(nc|ncat|netcat)\s+-[elv]",
        r"\bcurl\s+\S+\s*\|\s*(ba)?sh\b",
        r"__import__\s*\(\s*['\"]os",
        r"\{\{\s*config\b|\{\{.*__class__",
        r"\bO:\d+:\"",
        r"\brO0AB",
    )
]

REDACTED = "[contenu retiré par le filtre de sécurité]"


def sanitize(text: str) -> tuple[str, bool]:
    """Remplace les fragments offensifs. Renvoie (texte, a_été_filtré)."""
    filtered = False
    # Les blocs de code dans une explication sont retirés : l'explication reste conceptuelle
    if "```" in text or "`" in text:
        new = re.sub(r"```[\s\S]*?```", REDACTED, text)
        new = re.sub(r"`([^`]{25,})`", REDACTED, new)
        filtered = new != text
        text = new
    for pattern in _OFFENSIVE:
        if pattern.search(text):
            text = pattern.sub(REDACTED, text)
            filtered = True
    return text, filtered
