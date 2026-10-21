"""Règles complémentaires : familles de failles absentes de la première version.

SSRF et flux de données sur plusieurs lignes sont couverts par taint.py ; ici, les erreurs de
configuration repérables sur une ligne : jetons JWT non vérifiés, secrets d'application en dur,
cookies sans protection, injection NoSQL, pollution de prototype, chiffrement faible, CSRF désactivé,
fichiers temporaires prévisibles, XML sans protection contre les entités externes.
"""
import re

from ..models import Severity
from .rule_model import JS_LANGS, Rule

C, H, M, L = Severity.critical, Severity.high, Severity.medium, Severity.low


def _r(pattern: str, flags: int = 0) -> re.Pattern:
    return re.compile(pattern, flags)


EXTRA_RULES: list[Rule] = [
    # ------------------------------------------------------------------ jetons et secrets d'application
    Rule(
        "PY-JWT-NOVERIFY", ("python",),
        _r(r"jwt\.decode\([^)]*(verify_signature[\"']?\s*:\s*False|verify\s*=\s*False)"),
        "Jeton JWT accepté sans vérification", "CWE-347", C,
        "Le jeton JWT est décodé sans vérifier sa signature : n'importe qui peut en fabriquer un valide.",
        "Vérifier la signature avec la clé et une liste d'algorithmes fixe : jwt.decode(t, cle, algorithms=[\"RS256\"]).",
    ),
    Rule(
        "JS-JWT-NONE", JS_LANGS,
        _r(r"algorithms\s*:\s*\[[^\]]*[\"']none[\"']|jwt\.decode\(\s*[^)]*\)\s*;?\s*$"),
        "Jeton JWT accepté sans vérification", "CWE-347", C,
        "L'algorithme « none » (ou jwt.decode, qui ne vérifie rien) laisse accepter des jetons non signés.",
        "Utiliser jwt.verify avec une liste d'algorithmes explicite sans « none » : { algorithms: [\"HS256\"] }.",
    ),
    Rule(
        "PY-APP-SECRET", ("python",),
        _r(r"\b(secret_key|SECRET_KEY|JWT_SECRET(_KEY)?)\b\s*=\s*[\"'][^\"']{0,64}[\"']"),
        "Secret d'application écrit en dur", "CWE-798", H,
        "La clé qui signe les sessions ou les jetons est dans le code : qui la lit peut forger des sessions.",
        "Lire la clé depuis l'environnement ou un coffre-fort : app.secret_key = os.environ[\"FLASK_SECRET_KEY\"].",
    ),
    Rule(
        "JS-APP-SECRET", JS_LANGS,
        _r(r"\bsecret\s*:\s*[\"'`][^\"'`]+[\"'`]|jwt\.sign\([^,]+,\s*[\"'`][^\"'`]+[\"'`]"),
        "Secret d'application écrit en dur", "CWE-798", H,
        "La clé qui signe les sessions ou les jetons est dans le code : qui la lit peut forger des sessions.",
        "Lire la clé depuis l'environnement : secret: process.env.SESSION_SECRET.",
        # « secret: "Secret" » d'une table de libellés n'est pas une clé : contexte session / jeton exigé
        context_requires=_r(r"session|jwt|passport|cookie|sign\(|express|koa|fastify", re.I),
    ),
    # ------------------------------------------------------------------ cookies
    Rule(
        "PY-COOKIE", ("python",),
        # Appel complet sur la ligne : écrit sur plusieurs lignes, il peut fixer secure= plus bas
        _r(r"\.set_cookie\([^)]*\)"),
        "Cookie sans attributs de sécurité", "CWE-614", M,
        "Le cookie est créé sans Secure ni HttpOnly : il peut circuler en clair ou être lu par un script.",
        "Ajouter secure=True, httponly=True, samesite=\"Lax\" à set_cookie.",
        line_excludes=_r(r"secure\s*="),
    ),
    Rule(
        "JS-COOKIE", JS_LANGS,
        _r(r"\bres\.cookie\([^)]*\)|httpOnly\s*:\s*false|secure\s*:\s*false"),
        "Cookie sans attributs de sécurité", "CWE-614", M,
        "Le cookie est créé sans Secure ni HttpOnly : il peut circuler en clair ou être lu par un script.",
        "Passer { secure: true, httpOnly: true, sameSite: \"lax\" } à res.cookie.",
        line_excludes=_r(r"secure\s*:\s*(?!false)"),
    ),
    # ------------------------------------------------------------------ injections propres à JavaScript
    Rule(
        "JS-NOSQL", JS_LANGS,
        _r(r"\.(find|findOne|findOneAndUpdate|findOneAndDelete|updateOne|updateMany|deleteOne|deleteMany|count"
           r"|countDocuments|where)\(\s*\{[^}]*:\s*req\.(body|query|params)\.\w+|\$where\s*:"),
        "Injection NoSQL", "CWE-943", H,
        "Une valeur de la requête est passée telle quelle dans un filtre MongoDB : un objet comme "
        "{ \"$ne\": null } contourne la condition (connexion sans mot de passe, par exemple).",
        "Convertir les valeurs en chaînes (String(req.body.email)) ou valider le schéma avant la requête.",
    ),
    Rule(
        "JS-PROTO", JS_LANGS,
        _r(r"\b(_|lodash)\.(merge|mergeWith|defaultsDeep|set|setWith|zipObjectDeep)\([^)]*req\.(body|query|params)"
           r"|\bObject\.assign\([^)]*req\.(body|query)|\bdeepmerge\([^)]*req\.(body|query)"),
        "Pollution de prototype", "CWE-1321", H,
        "Fusionner un objet fourni par le client peut modifier Object.prototype (clé « __proto__ ») et "
        "changer le comportement de toute l'application.",
        "Ne copier que des champs attendus, ou fusionner dans Object.create(null) après validation du schéma.",
    ),
    # ------------------------------------------------------------------ chiffrement
    Rule(
        "JAVA-WEAKCIPHER", ("java",),
        _r(r"Cipher\.getInstance\(\s*\"((AES|DES|DESede|Blowfish)(/ECB/[^\"]*)?|[^\"]*/ECB/[^\"]*|DES[^\"]*|RC4"
           r"|ARCFOUR)\""),
        "Chiffrement faible", "CWE-327", M,
        "Le mode ECB (utilisé par défaut avec « AES ») ou les algorithmes DES / RC4 laissent fuiter la "
        "structure des données chiffrées.",
        "Utiliser un mode authentifié : Cipher.getInstance(\"AES/GCM/NoPadding\") avec un IV aléatoire.",
    ),
    Rule(
        "PY-WEAKCIPHER", ("python",),
        _r(r"\b(DES|DES3|ARC4|Blowfish)\.new\(|AES\.new\([^)]*MODE_ECB|modes\.ECB\("),
        "Chiffrement faible", "CWE-327", M,
        "Le mode ECB ou les algorithmes DES / RC4 laissent fuiter la structure des données chiffrées.",
        "Utiliser AES-GCM (cryptography : AESGCM) avec un nonce aléatoire.",
    ),
    # ------------------------------------------------------------------ configuration des frameworks
    Rule(
        "JAVA-CSRF-OFF", ("java",),
        _r(r"\.csrf\(\)\.disable\(\)|\.csrf\(\s*\w+\s*->\s*\w+\.disable\(\)\s*\)|AbstractHttpConfigurer::disable"),
        "Protection CSRF désactivée", "CWE-352", M,
        "Sans protection CSRF, un site tiers peut faire exécuter des actions à un utilisateur connecté.",
        "Garder la protection CSRF active (http.csrf(Customizer.withDefaults())), sauf API sans cookie de session.",
    ),
    # ------------------------------------------------------------------ fichiers temporaires et XML
    Rule(
        "PY-MKTEMP", ("python",),
        _r(r"\btempfile\.mktemp\(|(?<![\w.])mktemp\("),
        "Fichier temporaire prévisible", "CWE-377", L,
        "mktemp renvoie un nom sans créer le fichier : un autre processus peut le créer avant (course).",
        "Utiliser tempfile.NamedTemporaryFile() ou tempfile.mkstemp().",
    ),
    Rule(
        "PY-XXE", ("python",),
        _r(r"\b(etree|ET|ElementTree|minidom|xml\.dom\.minidom|sax)\.(fromstring|parse|parseString|XML|iterparse)\("),
        "Entités XML externes (XXE)", "CWE-611", M,
        "Le parseur XML traite les entités : un document piégé peut lire des fichiers du serveur (lxml) ou "
        "saturer la mémoire (« billion laughs »).",
        "Utiliser defusedxml, ou lxml avec XMLParser(resolve_entities=False, no_network=True).",
        file_excludes=_r(r"defusedxml"),
        line_excludes=_r(r"parser\s*=\s*\w+"),
    ),
    # ------------------------------------------------------------------ gabarits et expressions régulières
    Rule(
        "JS-TEMPLATE-NOESCAPE", JS_LANGS,
        _r(r"\bautoescape\s*:\s*false\b|\bnoEscape\s*:\s*true\b"),
        "Échappement automatique des gabarits désactivé", "CWE-79", H,
        "Le moteur de gabarits (Swig, Nunjucks, Handlebars) insère les variables sans les échapper : toute "
        "donnée affichée dans une page devient une XSS potentielle.",
        "Laisser l'échappement automatique activé (valeur par défaut) et n'insérer du HTML brut "
        "qu'explicitement, après nettoyage.",
    ),
    Rule(
        "PY-TEMPLATE-NOESCAPE", ("python",),
        _r(r"\bautoescape\s*=\s*False\b"),
        "Échappement automatique des gabarits désactivé", "CWE-79", H,
        "Jinja2 insère les variables sans les échapper : toute donnée affichée devient une XSS potentielle.",
        "Activer l'échappement : Environment(autoescape=select_autoescape()) ; le marquage |safe reste "
        "réservé à du HTML déjà nettoyé.",
    ),
    Rule(
        # Groupe répété dont le contenu est une classe répétée suivie d'éléments facultatifs :
        # « ([0-9]+)+ », « (\w+\s?)* », « ([a-z]*-?)+ » (une même chaîne se découpe de multiples façons).
        # « (\.\d+)* », « (/[\w.]+)+ » commencent par un séparateur fixe : sans ambiguïté, pas signalés.
        "REDOS", ("python", "javascript", "typescript", "php", "java", "csharp", "go"),
        _r(r"^(?=.*(RegExp\(|\bre\.(compile|match|search|fullmatch|sub|split|findall|finditer)\(|Pattern\."
           r"(compile|matches)\(|\.matches\(|\bpreg_\w+\(|regexp\.(MustCompile|Compile|MatchString)\(|new\s+Regex\("
           r"|Regex\.(IsMatch|Match|Replace)\(|[=(,:]\s*/[^/*\s]))"
           r".*\((?:\?:)?(?:\[(?:[^\]\\]|\\.)*\]|\\[dDwWsS]|\.)[+*]"
           r"(?:(?:\[(?:[^\]\\]|\\.)*\]|\\.|[^()\\|])[?*])*\)(?:[+*]|\{\d+,\})"),
        "Expression régulière vulnérable au déni de service (ReDoS)", "CWE-1333", M,
        "Une répétition imbriquée dans une autre fait exploser le temps d'évaluation sur certaines chaînes "
        "(retour arrière exponentiel) : une seule requête peut bloquer le serveur.",
        "Supprimer la répétition imbriquée (« ([0-9]+)+ » devient « [0-9]+ »), borner la longueur de "
        "l'entrée, ou utiliser un moteur sans retour arrière (RE2).",
    ),
]
