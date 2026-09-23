"""Référentiels : CWE → catégorie OWASP Top 10 (édition 2025)."""

CWE_DEPENDENCY = "CWE-1395"

OWASP_2025 = {
    "A01": "A01:2025 – Contrôle d'accès défaillant",
    "A02": "A02:2025 – Mauvaise configuration de sécurité",
    "A03": "A03:2025 – Défaillances de la chaîne d'approvisionnement logicielle",
    "A04": "A04:2025 – Défaillances cryptographiques",
    "A05": "A05:2025 – Injection",
    "A06": "A06:2025 – Conception non sécurisée",
    "A07": "A07:2025 – Défaillances d'authentification",
    "A08": "A08:2025 – Défaillances d'intégrité des logiciels et des données",
    "A09": "A09:2025 – Défaillances de journalisation et d'alerte",
    "A10": "A10:2025 – Mauvaise gestion des conditions exceptionnelles",
}

CWE_TO_OWASP = {
    "CWE-22": "A01",
    "CWE-98": "A05",
    "CWE-78": "A05",
    "CWE-79": "A05",
    "CWE-89": "A05",
    "CWE-94": "A05",
    "CWE-95": "A05",
    "CWE-1336": "A05",
    "CWE-117": "A09",
    "CWE-215": "A02",
    "CWE-489": "A02",
    "CWE-611": "A02",
    "CWE-942": "A02",
    "CWE-295": "A04",
    "CWE-327": "A04",
    "CWE-328": "A04",
    "CWE-338": "A04",
    "CWE-916": "A04",
    "CWE-798": "A07",
    "CWE-502": "A08",
    "CWE-1395": "A03",
}

CWE_NAMES = {
    "CWE-22": "Path Traversal",
    "CWE-78": "OS Command Injection",
    "CWE-79": "Cross-site Scripting",
    "CWE-89": "SQL Injection",
    "CWE-94": "Code Injection",
    "CWE-95": "Eval Injection",
    "CWE-98": "PHP File Inclusion",
    "CWE-117": "Log Injection",
    "CWE-215": "Debug Information Exposure",
    "CWE-295": "Improper Certificate Validation",
    "CWE-327": "Broken or Risky Cryptographic Algorithm",
    "CWE-328": "Weak Hash",
    "CWE-338": "Weak PRNG",
    "CWE-489": "Active Debug Code",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-611": "XML External Entity (XXE)",
    "CWE-798": "Hard-coded Credentials",
    "CWE-916": "Weak Password Hash",
    "CWE-942": "Permissive CORS Policy",
    "CWE-1336": "Server-Side Template Injection",
    "CWE-1395": "Vulnerable Third-Party Component",
}


def owasp_for(cwe: str | None) -> str | None:
    if not cwe:
        return None
    code = CWE_TO_OWASP.get(cwe)
    return OWASP_2025[code] if code else None


def references_for(cwe: str | None) -> list[str]:
    refs = []
    if cwe:
        refs.append(f"https://cwe.mitre.org/data/definitions/{cwe.split('-')[1]}.html")
    code = CWE_TO_OWASP.get(cwe or "")
    if code:
        refs.append("https://owasp.org/Top10/2025/")
    return refs
