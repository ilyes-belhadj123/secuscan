"""Règles statiques maison (couche 1).

Chaque règle est un motif appliqué ligne par ligne. Les règles sont volontairement
larges : la couche IA se charge ensuite d'écarter les faux positifs.
"""
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


def _r(pattern: str, flags: int = 0) -> re.Pattern:
    return re.compile(pattern, flags)


_SENSITIVE_CONTEXT = _r(r"token|secret|password|passwd|reset|otp|session|key|nonce|reference", re.I)
_SQL = r"(?i:SELECT|INSERT|UPDATE|DELETE)\b"

C, H, M, L = Severity.critical, Severity.high, Severity.medium, Severity.low

RULES: list[Rule] = [
    # ------------------------------------------------------------------ Python
    Rule(
        "PY-SQLI", ("python",),
        _r(r"\.execute(many)?\(\s*(f[\"']|[\"'][^\"']*[\"']\s*(%|\+|\.format))"),
        "Injection SQL", "CWE-89", C,
        "La requête SQL est construite en concaténant des valeurs au texte de la requête.",
        "Utiliser des requêtes paramétrées : cursor.execute(\"... WHERE x = ?\", (valeur,)).",
    ),
    Rule(
        "PY-CMDI", ("python",),
        _r(r"\bos\.(system|popen)\(|subprocess\.\w+\([^)]*shell\s*=\s*True"),
        "Injection de commande système", "CWE-78", C,
        "Une commande système est exécutée via un shell avec des données potentiellement contrôlées.",
        "Passer les arguments sous forme de liste à subprocess.run sans shell=True et valider les entrées.",
    ),
    Rule(
        "PY-EVAL", ("python",),
        _r(r"(?<![\w.])(eval|exec)\("),
        "Exécution de code dynamique", "CWE-95", C,
        "eval()/exec() exécute du code arbitraire si l'entrée est contrôlée par un utilisateur.",
        "Remplacer par un parseur dédié (ast.literal_eval, json.loads) ou une table de correspondance.",
    ),
    Rule(
        "PY-DESER", ("python",),
        _r(r"\b(pickle|cPickle|marshal|shelve)\.loads?\("),
        "Désérialisation non sécurisée", "CWE-502", C,
        "pickle permet l'exécution de code lors de la désérialisation de données non fiables.",
        "Utiliser un format de données sans exécution (JSON) et valider le schéma.",
    ),
    Rule(
        "PY-YAML", ("python",),
        _r(r"\byaml\.(unsafe_load|load)\((?![^)]*Safe)"),
        "Chargement YAML non sécurisé", "CWE-502", C,
        "yaml.load sans SafeLoader peut instancier des objets Python arbitraires.",
        "Utiliser yaml.safe_load().",
    ),
    Rule(
        "PY-SSTI", ("python",),
        _r(r"render_template_string\([^)]*(\+|%|\.format|f[\"'])"),
        "Injection de template côté serveur", "CWE-1336", C,
        "Un template est construit dynamiquement à partir de données utilisateur.",
        "Utiliser un template fixe et passer les données en variables de contexte.",
    ),
    Rule(
        "PY-SQLI-BUILD", ("python",),
        _r(rf"\"{_SQL}[^\"]*\"\s*(%|\+|\.format)|'{_SQL}[^']*'\s*(%|\+|\.format)|\bf[\"']{_SQL}[^\"']*\{{"),
        "Injection SQL", "CWE-89", C,
        "Une requête SQL est construite par concaténation ou interpolation avant d'être exécutée.",
        "Utiliser des requêtes paramétrées : cursor.execute(\"... WHERE x = ?\", (valeur,)).",
    ),
    Rule(
        "PY-REDIRECT", ("python",),
        _r(r"\bredirect\(\s*request\.(args|form|values|GET|POST)"),
        "Redirection ouverte", "CWE-601", M,
        "La destination de la redirection provient directement de la requête.",
        "N'accepter que des chemins relatifs internes ou une liste blanche de domaines.",
    ),
    Rule(
        "PY-PATH", ("python",),
        _r(r"\bopen\(\s*os\.path\.join\(|\bopen\([^)]*request\.|send_file\(\s*request\.|send_from_directory\([^)]*request\."),
        "Traversée de répertoire", "CWE-22", H,
        "Un chemin de fichier est construit à partir d'une donnée externe sans normalisation.",
        "Normaliser le chemin, vérifier qu'il reste dans le dossier autorisé, ou utiliser un identifiant.",
    ),
    Rule(
        "PY-WEAKHASH", ("python",),
        _r(r"\bhashlib\.(md5|sha1)\("),
        "Algorithme de hachage faible", "CWE-328", M,
        "MD5 et SHA-1 sont cassés pour les usages de sécurité (mots de passe, signatures).",
        "Pour des mots de passe : argon2 ou bcrypt. Pour l'intégrité : SHA-256 minimum.",
    ),
    Rule(
        "PY-TLS", ("python",),
        _r(r"\bverify\s*=\s*False"),
        "Vérification TLS désactivée", "CWE-295", H,
        "La validation du certificat serveur est désactivée : interception possible des échanges.",
        "Supprimer verify=False ; fournir un bundle de CA si nécessaire.",
    ),
    Rule(
        "PY-DEBUG", ("python",),
        _r(r"\.run\([^)]*debug\s*=\s*True"),
        "Mode debug activé", "CWE-489", H,
        "Le mode debug expose des traces détaillées et parfois une console interactive.",
        "Piloter le mode debug par variable d'environnement, désactivé en production.",
    ),
    # --------------------------------------------------------- JavaScript / TS
    Rule(
        "JS-SQLI", JS_LANGS,
        _r(r"\.(query|execute|raw)\(\s*(`[^`]*\$\{|[\"'][^\"']*[\"']\s*\+)"),
        "Injection SQL", "CWE-89", C,
        "La requête SQL est construite par interpolation de chaînes.",
        "Utiliser les paramètres liés du driver : db.query(\"... WHERE x = $1\", [valeur]).",
    ),
    Rule(
        "JS-SQLI-BUILD", JS_LANGS,
        _r(rf"`{_SQL}[^`]*\$\{{|\"{_SQL}[^\"]*\"\s*\+|'{_SQL}[^']*'\s*\+"),
        "Injection SQL", "CWE-89", C,
        "Une requête SQL est construite par interpolation ou concaténation avant d'être exécutée.",
        "Utiliser les paramètres liés du driver : db.query(\"... WHERE x = $1\", [valeur]).",
    ),
    Rule(
        "JS-XSS-SERVER", JS_LANGS,
        _r(r"\bres\.(send|write|end)\([^;]*req\.(query|params|body)"),
        "Cross-site scripting (XSS)", "CWE-79", H,
        "Une donnée de la requête est renvoyée telle quelle dans une réponse HTML.",
        "Utiliser un moteur de templates qui échappe par défaut, ou échapper la valeur avant envoi.",
    ),
    Rule(
        "JS-REDIRECT", JS_LANGS,
        _r(r"\bres\.redirect\(\s*req\.(query|params|body)"),
        "Redirection ouverte", "CWE-601", M,
        "La destination de la redirection provient directement de la requête.",
        "N'accepter que des chemins relatifs internes ou une liste blanche de domaines.",
    ),
    Rule(
        "JS-CMDI", JS_LANGS,
        _r(r"\b(exec|execSync)\(\s*(`[^`]*\$\{|[\"'][^\"']*[\"']\s*\+)"),
        "Injection de commande système", "CWE-78", C,
        "Une commande shell est construite avec des données externes.",
        "Utiliser execFile/spawn avec une liste d'arguments et une liste blanche de valeurs.",
    ),
    Rule(
        "JS-EVAL", JS_LANGS,
        _r(r"(?<![\w.])eval\(|new\s+Function\(|set(Timeout|Interval)\(\s*[\"'`]"),
        "Exécution de code dynamique", "CWE-95", C,
        "eval()/new Function() exécute du code arbitraire.",
        "Remplacer par un parseur d'expressions restreint ou une logique explicite.",
    ),
    Rule(
        "JS-XSS", JS_LANGS,
        _r(r"\.(innerHTML|outerHTML)\s*=|dangerouslySetInnerHTML|document\.write(ln)?\(|insertAdjacentHTML\("),
        "Cross-site scripting (XSS)", "CWE-79", H,
        "Du HTML est injecté dans la page sans échappement.",
        "Utiliser textContent, ou échapper / assainir le HTML (ex. DOMPurify).",
    ),
    Rule(
        "JS-PATH", JS_LANGS,
        _r(r"(sendFile|readFile(Sync)?|createReadStream)\([^;]*req\.(query|params|body)"),
        "Traversée de répertoire", "CWE-22", H,
        "Un chemin de fichier dépend directement de la requête HTTP.",
        "Résoudre le chemin, vérifier qu'il reste dans le dossier autorisé (path.resolve + startsWith).",
    ),
    Rule(
        "JS-CORS", JS_LANGS,
        _r(r"Access-Control-Allow-Origin[\"']\s*,\s*[\"']\*|origin\s*:\s*[\"']\*[\"']"),
        "Politique CORS permissive", "CWE-942", M,
        "Toutes les origines sont autorisées à appeler l'API depuis un navigateur.",
        "Restreindre à une liste explicite d'origines de confiance.",
    ),
    Rule(
        "JS-RANDOM", JS_LANGS,
        _r(r"Math\.random\(\)"),
        "Générateur aléatoire non cryptographique", "CWE-338", L,
        "Math.random() est prévisible et ne doit pas servir à générer des jetons.",
        "Utiliser crypto.randomUUID() ou crypto.getRandomValues().",
        context_requires=_SENSITIVE_CONTEXT,
    ),
    # --------------------------------------------------------------------- PHP
    Rule(
        "PHP-SQLI", ("php",),
        _r(r"(mysqli_query|mysql_query|pg_query|->query|->exec)\s*\([^;]*(\.\s*\$|\$_(GET|POST|REQUEST|COOKIE)|\"[^\"]*\$\w+)"),
        "Injection SQL", "CWE-89", C,
        "La requête SQL concatène des variables PHP.",
        "Utiliser PDO ou mysqli avec requêtes préparées (prepare + bind_param).",
    ),
    Rule(
        "PHP-XSS", ("php",),
        _r(r"\b(echo|print)\b[^;]*\$_(GET|POST|REQUEST|COOKIE)"),
        "Cross-site scripting (XSS)", "CWE-79", H,
        "Une donnée de la requête est renvoyée dans la page sans échappement.",
        "Échapper systématiquement avec htmlspecialchars($v, ENT_QUOTES, 'UTF-8').",
        line_excludes=_r(r"htmlspecialchars|htmlentities|intval\(|\(int\)"),
    ),
    Rule(
        "PHP-XSS-STORED", ("php",),
        _r(r"\b(echo|print)\b[^;]*\.\s*\$(?!_)\w+\s*\["),
        "Cross-site scripting (XSS) stocké", "CWE-79", M,
        "Une valeur issue de la base ou d'un tableau est affichée sans échappement.",
        "Échapper systématiquement avec htmlspecialchars($v, ENT_QUOTES, 'UTF-8').",
        line_excludes=_r(r"htmlspecialchars|htmlentities|intval\(|\(int\)"),
    ),
    Rule(
        "PHP-REDIRECT", ("php",),
        _r(r"\bheader\(\s*[\"']Location:[^;]*\$_(GET|POST|REQUEST)"),
        "Redirection ouverte", "CWE-601", M,
        "La destination de la redirection provient directement de la requête.",
        "N'accepter que des chemins relatifs internes ou une liste blanche de domaines.",
    ),
    Rule(
        "PHP-CMDI", ("php",),
        _r(r"(?<!->)(?<!::)\b(system|exec|shell_exec|passthru|popen|proc_open)\s*\([^;]*\$"),
        "Injection de commande système", "CWE-78", C,
        "Une commande système est construite avec une variable.",
        "Éviter le shell ; sinon escapeshellarg() et liste blanche des valeurs.",
        line_excludes=_r(r"escapeshellarg|escapeshellcmd"),
    ),
    Rule(
        "PHP-LFI", ("php",),
        _r(r"\b(include|require)(_once)?\b[\s(]*[^;]*\$"),
        "Inclusion de fichier dynamique", "CWE-98", C,
        "Le fichier inclus dépend d'une variable : inclusion de fichiers arbitraires possible.",
        "Utiliser une table de correspondance fixe (liste blanche) des modules autorisés.",
    ),
    Rule(
        "PHP-DESER", ("php",),
        _r(r"\bunserialize\s*\([^;]*\$_(GET|POST|REQUEST|COOKIE)"),
        "Désérialisation non sécurisée", "CWE-502", C,
        "unserialize() sur une donnée client permet l'injection d'objets PHP.",
        "Utiliser json_decode() ; à défaut, unserialize($v, ['allowed_classes' => false]).",
    ),
    Rule(
        "PHP-WEAKHASH", ("php",),
        _r(r"\b(md5|sha1)\s*\("),
        "Hachage de mot de passe faible", "CWE-916", H,
        "MD5/SHA-1 sont inadaptés au stockage de mots de passe.",
        "Utiliser password_hash() et password_verify().",
        context_requires=_r(r"pass", re.I),
    ),
    # -------------------------------------------------------------------- Java
    Rule(
        "JAVA-SQLI", ("java",),
        _r(r"\.(executeQuery|executeUpdate|execute|prepareStatement|createQuery)\(\s*\"[^\"]*\"\s*\+"),
        "Injection SQL", "CWE-89", C,
        "La requête SQL est construite par concaténation de chaînes.",
        "Utiliser PreparedStatement avec des paramètres (?) et setString().",
    ),
    Rule(
        "JAVA-SQLI-BUILD", ("java",),
        _r(rf"\"{_SQL}[^\"]*\"\s*\+"),
        "Injection SQL", "CWE-89", C,
        "Une requête SQL est construite par concaténation avant d'être exécutée.",
        "Utiliser PreparedStatement avec des paramètres (?) et setString().",
    ),
    Rule(
        "JAVA-XSS", ("java",),
        _r(r"getWriter\(\)\.(print|println|write)\([^;]*getParameter\("),
        "Cross-site scripting (XSS)", "CWE-79", H,
        "Un paramètre de la requête est écrit tel quel dans la réponse HTML.",
        "Échapper la sortie (ex. OWASP Java Encoder : Encode.forHtml) ou utiliser un moteur de templates.",
    ),
    Rule(
        "JAVA-REDIRECT", ("java",),
        _r(r"sendRedirect\([^;]*getParameter\("),
        "Redirection ouverte", "CWE-601", M,
        "La destination de la redirection provient directement de la requête.",
        "N'accepter que des chemins relatifs internes ou une liste blanche de domaines.",
    ),
    Rule(
        "JAVA-PATH", ("java",),
        _r(r"new\s+File(InputStream|Reader)?\([^;]*getParameter\(|Paths\.get\([^;]*getParameter\("),
        "Traversée de répertoire", "CWE-22", H,
        "Un chemin de fichier est construit à partir d'un paramètre de la requête.",
        "Normaliser le chemin (toRealPath) et vérifier qu'il reste dans le dossier autorisé.",
    ),
    Rule(
        "JAVA-CMDI", ("java",),
        _r(r"Runtime\.getRuntime\(\)\.exec\(|new\s+ProcessBuilder\([^)]*\+"),
        "Injection de commande système", "CWE-78", C,
        "Une commande système est exécutée avec des données concaténées.",
        "Utiliser ProcessBuilder avec une liste d'arguments et valider les entrées.",
    ),
    Rule(
        "JAVA-DESER", ("java",),
        _r(r"new\s+ObjectInputStream\("),
        "Désérialisation non sécurisée", "CWE-502", C,
        "La désérialisation Java native de données non fiables permet l'exécution de code.",
        "Utiliser JSON avec un schéma, ou un ObjectInputFilter en liste blanche.",
    ),
    Rule(
        "JAVA-XXE", ("java",),
        _r(r"(DocumentBuilderFactory|SAXParserFactory|XMLInputFactory)\.newInstance\(\)"),
        "Entités XML externes (XXE)", "CWE-611", H,
        "Le parseur XML accepte les entités externes par défaut.",
        "Activer disallow-doctype-decl et désactiver les entités externes sur la factory.",
        file_excludes=_r(r"disallow-doctype-decl|FEATURE_SECURE_PROCESSING|SUPPORT_DTD"),
    ),
    Rule(
        "JAVA-WEAKHASH", ("java",),
        _r(r"MessageDigest\.getInstance\(\s*\"(MD5|SHA-?1)\""),
        "Algorithme de hachage faible", "CWE-328", M,
        "MD5/SHA-1 ne garantissent plus l'intégrité face à un attaquant.",
        "Utiliser SHA-256 (MessageDigest.getInstance(\"SHA-256\")).",
    ),
    Rule(
        "JAVA-RANDOM", ("java",),
        _r(r"new\s+Random\("),
        "Générateur aléatoire non cryptographique", "CWE-338", L,
        "java.util.Random est prévisible et ne doit pas générer de valeurs sensibles.",
        "Utiliser java.security.SecureRandom.",
        context_requires=_SENSITIVE_CONTEXT,
    ),
    Rule(
        "JAVA-LOGI", ("java",),
        _r(r"\bLOG(GER)?\.(info|warn|error|debug)\([^;]*\+"),
        "Journalisation de données non maîtrisées", "CWE-117", L,
        "Des données externes sont écrites telles quelles dans les journaux.",
        "Utiliser des paramètres ({}) et neutraliser les retours à la ligne ; maintenir Log4j à jour.",
    ),
]

RULES_BY_ID = {rule.id: rule for rule in RULES}
