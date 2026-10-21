"""Suivi des données dans un fichier (analyse de « teinte » simplifiée).

Les règles par motif ne voient qu'une ligne : `$name = $_GET['n'];` puis `echo $name;` leur échappe.
Ici, une variable qui reçoit une entrée utilisateur (source) est suivie à travers les affectations,
concaténations et interpolations, jusqu'à une opération dangereuse (puits) : requête SQL, affichage
HTML, commande système, requête réseau (SSRF), accès fichier, redirection.

Simplifications assumées (la couche IA juge ensuite chaque alerte) :
- analyse dans l'ordre du fichier ; les variables suivies repartent de zéro à chaque fonction ;
- une valeur passée par une fonction de nettoyage connue (int(), htmlspecialchars, escapeHtml,
  encodeURIComponent, basename…) n'est plus teintée pour la suite de l'expression ;
- pour SQL, commandes, SSRF et fichiers, seul le premier argument compte : une valeur passée en
  paramètre séparé d'une requête préparée n'est pas une injection.
"""
import re
from dataclasses import dataclass

from ..ingest import SourceFile
from ..models import Severity

C, H, M = Severity.critical, Severity.high, Severity.medium


@dataclass(frozen=True)
class Sink:
    rule_id: str
    kind: str  # sql | xss | cmd | ssrf | path | redirect
    pattern: re.Pattern  # s'arrête juste après la parenthèse ouvrante de l'appel
    first_arg: bool = True  # n'examiner que le premier argument (sinon : toute la fin de ligne)


@dataclass(frozen=True)
class ParamSink:
    """Résumé d'une fonction : son paramètre n° `param` atteint une opération dangereuse."""
    param: int
    rule_id: str
    kind: str
    file: str
    line: int
    function: str


@dataclass(frozen=True)
class CallHit:
    """Appel d'une fonction résumée avec une donnée non fiable à la position du paramètre."""
    sink: ParamSink
    line: int
    variable: str
    origin: int  # ligne d'origine, ou -(n + 1) si la donnée est le paramètre n de la fonction analysée


_CALL = re.compile(r"(?<![\w$])([A-Za-z_$][\w$]*)\s*\(")  # en début de mot : coût linéaire
# Nom de la fonction définie sur une ligne de début de fonction (ce n'est pas un appel)
_DEFINED_NAME = re.compile(r"(?:\bdef|\bfunction|\bfunc(?:\s*\([^)]*\))?|[\w<>\[\],?]+)\s+(\w+)\s*\(")


@dataclass(frozen=True)
class FlowFinding:
    rule_id: str
    kind: str
    line: int
    variable: str
    source_line: int
    assigned_line: int = 0  # dernière ligne où la variable a été construite (0 : source directe)


KINDS = {
    "sql": ("Injection SQL", "CWE-89", C),
    "xss": ("Cross-site scripting (XSS)", "CWE-79", H),
    "cmd": ("Injection de commande système", "CWE-78", C),
    "ssrf": ("Falsification de requête côté serveur (SSRF)", "CWE-918", H),
    "path": ("Traversée de répertoire", "CWE-22", H),
    "redirect": ("Redirection ouverte", "CWE-601", M),
    "lfi": ("Inclusion de fichier dynamique", "CWE-98", C),
}
JS = ("javascript", "typescript")
# Valeur choisie dans une liste blanche (« in_array($p, $autorises, true) ? $p : 'home' ») : sûre
_ALLOWLIST = re.compile(r"\bin_array\(|\.includes\(\s*[\w$.]+\s*\)\s*\?|\.contains\(\s*\w+\s*\)\s*\?"
                        r"|\bif\s+[\w.]+\s+in\s+[\w.]+\s+else\b")
_r = re.compile

SOURCES = {
    "python": _r(r"\brequest\.(args|form|values|json|get_json\(|data|get_data\(|headers|cookies|files|GET|POST|body)"
                 r"|(?<![\w.])input\("),
    "javascript": _r(r"\breq\.(query|body|params|headers|cookies)\b|\blocation\.(search|hash)\b|"
                     r"\bURLSearchParams\(|\bdocument\.(URL|referrer|cookie)\b"),
    "php": _r(r"\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)\b|php://input"),
    "java": _r(r"\.getParameter(Values)?\(|\.getHeader\(|\.getQueryString\(|\.getInputStream\("),
}

# Nettoyages qui rendent une valeur sûre : leur appel est remplacé par une valeur neutre
SANITIZERS = {
    "python": _r(r"\b(int|float|bool|len|uuid\.UUID|html\.escape|markupsafe\.escape|escape|quote|quote_plus|"
                 r"shlex\.quote|secure_filename|os\.path\.basename|bleach\.clean)\((?:[^()]|\([^()]*\))*\)"),
    "javascript": _r(r"\b(parseInt|parseFloat|Number|Boolean|String|encodeURIComponent|encodeURI|escapeHtml|"
                     r"escape|validator\.escape|path\.basename|DOMPurify\.sanitize|sanitizeHtml|he\.encode)"
                     r"\((?:[^()]|\([^()]*\))*\)"),
    "php": _r(r"\b(intval|floatval|boolval|htmlspecialchars|htmlentities|strip_tags|escapeshellarg|"
              r"escapeshellcmd|basename|urlencode|rawurlencode|filter_var|mysqli_real_escape_string|md5|sha1|hash|crc32)"
              r"\s*\((?:[^()]|\([^()]*\))*\)"
              r"|\$\w+->(quote|real_escape_string)\((?:[^()]|\([^()]*\))*\)|\(int\)\s*\$\w+"),
    "java": _r(r"\b(Integer\.parseInt|Long\.parseLong|Integer\.valueOf|Long\.valueOf|UUID\.fromString|"
               r"URLEncoder\.encode|Encode\.forHtml\w*|HtmlUtils\.htmlEscape|StringEscapeUtils\.escapeHtml4|"
               r"FilenameUtils\.getName)\((?:[^()]|\([^()]*\))*\)"),
}

# Type Java / C# sans espace ambigu (pas de retour arrière catastrophique sur « public public … ») :
# nom qualifié, paramètres génériques sur deux niveaux (« Map<String, List<Integer>> »), tableaux
_TYPE = r"[\w.]+(?:<[^<>=;()]*(?:<[^<>=;()]*>[^<>=;()]*)*>)?\??(?:\[\])*"
# Lignes plus longues ignorées : aucun code écrit à la main n'en contient (le code minifié est écarté)
MAX_LINE_LENGTH = 2000

# Affectations : groupe 1 = nom(s) affecté(s), groupe 2 = expression
ASSIGN = {
    "python": _r(r"^\s*([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s*(?::[^=\n]*)?\+?=(?!=)\s*(.+)$"),
    "javascript": _r(r"^\s*(?:(?:const|let|var)\s+)?(\{[^}]*\}|\[[^\]]*\]|[A-Za-z_$][\w$]*)\s*(?::\s*[\w<>\[\]|]+)?"
                     r"\s*\+?=(?![=>])\s*(.+)$"),
    "php": _r(r"^\s*\$(\w+)\s*\.?=(?![=>])\s*(.+)$"),
    "java": _r(rf"^\s*(?:final\s+)?(?:{_TYPE}\s+)?([A-Za-z_]\w*)\s*\+?=(?!=)\s*(.+)$"),
}

SINKS: dict[str, list[Sink]] = {
    "python": [
        Sink("PY-SQLI-FLOW", "sql", _r(r"\.execute(many)?\(|\.raw\(|\btext\(")),
        Sink("PY-CMDI-FLOW", "cmd", _r(r"\bos\.(system|popen)\(|subprocess\.\w+\((?=.*shell\s*=\s*True)")),
        Sink("PY-SSRF", "ssrf", _r(r"\b(requests|httpx|session|client)\.(get|post|put|delete|patch|head|request)\("
                                   r"|\burlopen\(")),
        Sink("PY-PATH-FLOW", "path", _r(r"(?<![\w.])open\(|\bsend_file\(|\bos\.remove\(")),
        Sink("PY-REDIRECT-FLOW", "redirect", _r(r"\bredirect\(")),
        # render_template_string : injection de template, déjà couverte par la règle PY-SSTI
        Sink("PY-XSS-FLOW", "xss", _r(r"\b(make_response|Markup|HttpResponse)\(")),
        Sink("PY-XSS-FLOW", "xss", _r(r"^\s*return\s+f?[\"'][^\"']*<\w"), first_arg=False),
    ],
    "javascript": [
        Sink("JS-SQLI-FLOW", "sql", _r(r"\.(query|execute|raw)\(|\.\$queryRawUnsafe\(")),
        Sink("JS-CMDI-FLOW", "cmd", _r(r"\b(exec|execSync)\(|child_process\.exec\w*\(")),
        Sink("JS-SSRF", "ssrf", _r(r"\b(fetch|got|needle)\(|\baxios(\.(get|post|put|delete|patch|request))?\("
                                   r"|\b(needle|got|superagent|request)\.(get|post|put|delete|patch|head|request)\("
                                   r"|\bhttps?\.(get|request)\(")),
        Sink("JS-PATH-FLOW", "path", _r(r"\bfs\.(readFile|readFileSync|createReadStream|writeFile|unlink)\w*\("
                                        r"|\bres\.(sendFile|download)\(")),
        Sink("JS-REDIRECT-FLOW", "redirect", _r(r"\bres\.redirect\(|\blocation\.(assign|replace)\(")),
        Sink("JS-XSS-FLOW", "xss", _r(r"\bres\.(send|write|end)\(|\.(innerHTML|outerHTML)\s*=|document\.write\("
                                      r"|insertAdjacentHTML\("), first_arg=False),
    ],
    "php": [
        Sink("PHP-SQLI-FLOW", "sql", _r(r"\b(mysqli_query|pg_query)\(\s*\$\w+(\[[^\]]*\])?\s*,"
                                        r"|->(query|exec|multi_query)\(")),
        Sink("PHP-CMDI-FLOW", "cmd", _r(r"(?<![$\w>])(system|exec|shell_exec|passthru|popen|proc_open)\(")),
        Sink("PHP-SSRF", "ssrf", _r(r"(?<![$\w>])(curl_init|get_headers)\(|(?<![$\w>])(file_get_contents|fopen)\("
                                    r"(?!\s*([\"']php://|__DIR__|[A-Z][A-Z0-9_]+\b|[\"'](?![a-z]+://)))")),
        Sink("PHP-PATH-FLOW", "path", _r(r"(?<![$\w>])(file_get_contents|fopen)\("
                                         r"(?=\s*(__DIR__|[A-Z][A-Z0-9_]+\b|[\"'](?![a-z]+://|php://)))")),
        Sink("PHP-LFI-FLOW", "lfi", _r(r"(?<![$\w>])(include|include_once|require|require_once)\b\s*\(?"),
             first_arg=False),
        Sink("PHP-PATH-FLOW", "path", _r(r"(?<![$\w>])(readfile|unlink|file)\(")),
        Sink("PHP-REDIRECT-FLOW", "redirect", _r(r"(?i)\bheader\s*\(\s*[\"']Location\s*:"), first_arg=False),
        Sink("PHP-XSS-FLOW", "xss", _r(r"^\s*(echo|print)\b|<\?=|\bprintf\("), first_arg=False),
        # Balise concaténée (« '<pre>' . $x », « $x . '</pre>' ») ou interpolée (« "<pre>{$x}" ») ;
        # pas une balise passée en argument (« str_replace('<script>', '', $x) »)
        Sink("PHP-XSS-FLOW", "xss", _r(r"^\s*\$\w+\s*\.?=(?![=>])(?=\s*(?:[\"']|\$\w+(?:\[[^\]]*\])?\s*\.))(?=[^;]*("
                                      r"[\"'][^\"']*</?[a-zA-Z][\w-]*[\s>/][^\"']*[\"']\s*\."
                                      r"|\.\s*[\"'][^\"']*</?[a-zA-Z][\w-]*[\s>/]"
                                      r"|\"[^\"]*</?[a-zA-Z][\w-]*[\s>/][^\"]*\$))"), first_arg=False),
    ],
    "java": [
        # (« super.execute(…) » : méthode de la classe parente, pas une requête)
        Sink("JAVA-SQLI-FLOW", "sql", _r(r"(?<!super)(?<!this)\.(executeQuery|executeUpdate|execute|addBatch|"
                                         r"prepareStatement|createQuery|createNativeQuery)\(")),
        Sink("JAVA-CMDI-FLOW", "cmd", _r(r"\.exec\(|new\s+ProcessBuilder\(")),
        Sink("JAVA-SSRF", "ssrf", _r(r"new\s+URL\(|URI\.create\(|\.(getForObject|getForEntity)\(")),
        # new File(dossier, nom), Paths.get(base, nom) : le nom est souvent le 2e argument
        Sink("JAVA-PATH-FLOW", "path", _r(r"new\s+(File|FileInputStream|FileReader|FileOutputStream)\(|Paths\.get\(|"
                                          r"Path\.of\("), first_arg=False),
        Sink("JAVA-REDIRECT-FLOW", "redirect", _r(r"\.sendRedirect\(")),
        # Spring MVC : « new ModelAndView("redirect:" + url) », « return "redirect:" + url; »
        Sink("JAVA-REDIRECT-FLOW", "redirect", _r(r"(new\s+(ModelAndView|RedirectView)\(|\breturn\s+)(?=\"redirect:)"
                                                  r"|new\s+RedirectView\("), first_arg=False),
        Sink("JAVA-XSS-FLOW", "xss", _r(r"\.getWriter\(\)\.(print|println|write)\("), first_arg=False),
    ],
}

# Chaînes sans interpolation, retirées avant de chercher des noms de variables (« name » dans un texte)
# Les chaînes qui interpolent (groupe « keep ») sont reconnues d'abord et conservées telles quelles :
# « "… WHERE id = '$id'" » (PHP), f"… '{uid}'" (Python), `… '${id}'` (JavaScript) gardent leur variable.
_DQ, _SQ = r"\"(?:[^\"\\]|\\.)*\"", r"'(?:[^'\\]|\\.)*'"
_PLAIN_STRINGS = {
    "python": _r(rf"(?P<keep>(?<!\w)(?:[fF][rRbB]?|[rRbB][fF])(?:{_DQ}|{_SQ}))|(?<!\w)[rRbBuU]{{0,2}}(?:{_DQ}|{_SQ})"),
    "javascript": _r(rf"(?P<keep>`(?:[^`\\]|\\.)*`)|{_DQ}|{_SQ}"),
    "php": _r(rf"(?P<keep>{_DQ})|{_SQ}"),  # les guillemets doubles interpolent les variables
    "java": _r(_DQ),
}


def _strip_plain_strings(pattern: re.Pattern, expr: str) -> str:
    return pattern.sub(lambda m: m.group(0) if m.groupdict().get("keep") else '""', expr)
# Début d'une fonction ou d'une route : les variables suivies repartent de zéro
_FUNCTION_START = {
    "python": _r(r"^\s*(async\s+)?def\s"),
    "javascript": _r(r"\bfunction\b[^(]*\(|=>\s*\{\s*$"),
    "php": _r(r"\bfunction\s+\w+\s*\("),
    "java": _r(r"^(?!\s*(try|if|for|while|switch|catch|synchronized|return|else|do|new)\b)"
               r"\s*(?:(?:public|private|protected|static|final|synchronized|abstract|default)\s+)*"
               rf"{_TYPE}\s+\w+\s*\([^;]*\)\s*(?:throws\s+[\w.]+(?:\s*,\s*[\w.]+)*)?\s*\{{?\s*$"),
}
# Paramètres reçus du client par annotation (Spring) : teintés dès la signature
# Le type n'est pas numérique, booléen, UUID ou date : une telle valeur ne peut pas porter de texte
_ANNOTATED_PARAM = _r(r"@(RequestParam|PathVariable|RequestBody|RequestHeader)(\([^)]*\))?\s+(final\s+)?"
                      r"(?!(?:int|long|short|byte|double|float|boolean|Integer|Long|Short|Byte|Double|Float|Boolean"
                      r"|BigDecimal|BigInteger|UUID|LocalDate|LocalDateTime|Instant)\s)[\w<>\[\]]+\s+(\w+)")
_SPRING_MAPPING = _r(r"@(Get|Post|Put|Delete|Patch|Request)Mapping\b")
_SPRING_TEXT_PARAM = _r(r"(?:^|,)\s*(?:final\s+)?String\s+(\w+)\s*(?=[,)])")
# ---------------------------------------------------------------------- C# (ASP.NET Core) et Go
SOURCES["csharp"] = _r(r"\bRequest\.(Query|Form|Body|Headers|Cookies|RouteValues)\b|HttpContext\.Request\.")
SOURCES["go"] = _r(r"\br\.URL\.Query\(\)|\br\.(FormValue|PostFormValue)\(|\br\.(Form|PostForm|Body)\b|"
                   r"\br\.Header\.Get\(|\bmux\.Vars\(|\bc\.(Query|DefaultQuery|Param|PostForm|GetHeader|FormValue)\(")
SANITIZERS["csharp"] = _r(r"\b(HtmlEncoder\.Default\.Encode|WebUtility\.HtmlEncode|HttpUtility\.HtmlEncode|"
                          r"Uri\.EscapeDataString|Path\.GetFileName|int\.Parse|long\.Parse|Guid\.Parse|"
                          r"Convert\.ToInt32|Convert\.ToInt64)\((?:[^()]|\([^()]*\))*\)")
SANITIZERS["go"] = _r(r"\b(html\.EscapeString|template\.HTMLEscapeString|url\.PathEscape|url\.QueryEscape|"
                      r"filepath\.Base|path\.Base|strconv\.(Atoi|ParseInt|ParseUint|ParseFloat|ParseBool))\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\)"
                      # sortie d'un programme lancé sans shell : produite par le programme, pas par le client
                      r"|exec\.Command(Context)?\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\)\.(Output|CombinedOutput)\(\)")
ASSIGN["csharp"] = _r(rf"^\s*(?:using\s+)?(?:(?:var|{_TYPE})\s+)?([A-Za-z_]\w*)\s*\+?=(?![=>])\s*(.+)$")
ASSIGN["go"] = _r(r"^\s*([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s*:?=(?!=)\s*(.+)$")
SINKS["csharp"] = [
    Sink("CS-SQLI-FLOW", "sql", _r(r"new\s+SqlCommand\(|\.(ExecuteSqlRaw|ExecuteSqlRawAsync|FromSqlRaw|SqlQueryRaw)\(")),
    Sink("CS-SQLI-FLOW", "sql", _r(r"\.CommandText\s*="), first_arg=False),
    Sink("CS-CMDI-FLOW", "cmd", _r(r"Process\.Start\(|\.Arguments\s*="), first_arg=False),
    Sink("CS-SSRF", "ssrf", _r(r"\.(GetAsync|GetStringAsync|GetByteArrayAsync|GetStreamAsync|PostAsync|DeleteAsync)\("
                               r"|new\s+Uri\(|WebRequest\.Create\(")),
    Sink("CS-PATH-FLOW", "path", _r(r"\bFile\.(ReadAllText|ReadAllBytes|ReadAllLines|OpenRead|Open|WriteAllText|Delete)\("
                                    r"|new\s+FileStream\(|\bPhysicalFile\(")),
    Sink("CS-REDIRECT-FLOW", "redirect", _r(r"(?<![\w.])Redirect(Permanent)?\(")),
    # Content(x) renvoie du texte brut par défaut : XSS seulement avec un type « text/html »
    Sink("CS-XSS-FLOW", "xss", _r(r"(?<![\w.])Content\((?=.*text/html)|\bHtml\.Raw\(|\.Response\.WriteAsync\(")),
]
SINKS["go"] = [
    Sink("GO-SQLI-FLOW", "sql", _r(r"\.(QueryContext|QueryRowContext|ExecContext)\(\s*[^,]+,"
                                   r"|\.(Query|QueryRow|Exec|Raw)\(")),
    Sink("GO-CMDI-FLOW", "cmd", _r(r"exec\.Command(Context)?\(\s*\"(sh|bash|/bin/sh|/bin/bash|cmd|cmd\.exe|powershell)\"\s*,"
                                   r"\s*\"(-c|/c|-Command)\"\s*,")),
    Sink("GO-CMDI-FLOW", "cmd", _r(r"exec\.Command\(")),  # nom du programme fourni par le client
    Sink("GO-SSRF", "ssrf", _r(r"\bhttp\.(Get|Post|Head|PostForm)\(|\bhttp\.NewRequest\(\s*[^,]+,|\bclient\.(Get|Post)\(")),
    Sink("GO-PATH-FLOW", "path", _r(r"\bos\.(Open|ReadFile|Create|OpenFile|Remove|WriteFile)\(|\bioutil\.ReadFile\("
                                    r"|\bhttp\.ServeFile\([^,]+,[^,]+,")),
    Sink("GO-REDIRECT-FLOW", "redirect", _r(r"\bhttp\.Redirect\([^,]+,[^,]+,|\bc\.Redirect\([^,]+,")),
    Sink("GO-XSS-FLOW", "xss", _r(r"\bfmt\.Fprint(f|ln)?\(\s*w\s*,|\bw\.Write\(|\bio\.WriteString\(\s*w\s*,"
                                  r"|\btemplate\.HTML\("), first_arg=False),
]
_PLAIN_STRINGS["csharp"] = _r(r"(?P<keep>\$@?\"(?:[^\"\\]|\\.)*\")|@?\"(?:[^\"\\]|\\.)*\"")  # $"…" interpole
_PLAIN_STRINGS["go"] = _r(r"\"(?:[^\"\\]|\\.)*\"|`[^`]*`")
_FUNCTION_START["csharp"] = _r(r"^(?!\s*(try|if|for|foreach|while|switch|catch|using|lock|return)\b)"
                               r"\s*(public|private|protected|internal)\s+(static\s+|async\s+|virtual\s+|override\s+)*"
                               rf"{_TYPE}\s+\w+\s*\(")
_FUNCTION_START["go"] = _r(r"^\s*func\b")
# ASP.NET : les paramètres texte d'une action de contrôleur sont remplis à partir de la requête
_CS_CONTROLLER = _r(r":\s*(Controller|ControllerBase)\b|\[ApiController\]")
_CS_ACTION = _r(rf"^\s*public\s+(async\s+)?(virtual\s+)?{_TYPE}\s+\w+\s*\(([^)]*)\)")
_CS_TEXT_PARAM = _r(r"(\[From\w+[^\]]*\]\s*)?\b(string|object|dynamic|IFormFile|JsonElement)\??\s+(\w+)")

_COMMENT = _r(r"^\s*(#|//|/?\*)")
for table in (SOURCES, SANITIZERS, ASSIGN, SINKS, _PLAIN_STRINGS, _FUNCTION_START):
    table["typescript"] = table["javascript"]


# ---------------------------------------------------------------------- nettoyages par type de faille
# Un nettoyage ne protège que de certaines failles : htmlspecialchars() rend une valeur sûre dans une
# page HTML, pas dans une requête SQL ni une commande. Chaque entrée : fonctions, failles couvertes
# (None : toutes, la valeur devient un nombre, un identifiant ou une empreinte).
ALL_KINDS = frozenset(KINDS)
# Encodage d'URL d'un composant : plus de ' " < ; / .. ni de « https:// » utilisable comme adresse
_ENCODED = frozenset({"xss", "sql", "cmd", "path", "lfi", "ssrf", "redirect"})
_ARGS = r"\s*\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\)"
_SANITIZER_TABLE: dict[str, list[tuple[str, frozenset | None]]] = {
    "python": [
        (r"\b(?:int|float|bool|len|uuid\.UUID)" + _ARGS, None),
        (r"\b(?:html\.escape|markupsafe\.escape|escape|bleach\.clean)" + _ARGS, frozenset({"xss"})),
        (r"(?<![\w.])(?:quote|quote_plus|urllib\.parse\.quote|urllib\.parse\.quote_plus)" + _ARGS, _ENCODED),
        (r"\bshlex\.quote" + _ARGS, frozenset({"cmd"})),
        (r"\b(?:secure_filename|os\.path\.basename)" + _ARGS, frozenset({"path", "lfi"})),
    ],
    "javascript": [
        (r"\b(?:parseInt|parseFloat|Number|Boolean)" + _ARGS, None),
        (r"\bencodeURIComponent" + _ARGS, _ENCODED),
        (r"\bencodeURI" + _ARGS, frozenset({"xss"})),
        (r"\b(?:escapeHtml|escape|validator\.escape|DOMPurify\.sanitize|sanitizeHtml|he\.encode)" + _ARGS,
         frozenset({"xss"})),
        (r"\bpath\.basename" + _ARGS, frozenset({"path", "lfi"})),
    ],
    "php": [
        (r"\b(?:intval|floatval|boolval|md5|sha1|hash|crc32|filter_var)" + _ARGS + r"|\(int\)\s*\$\w+", None),
        (r"\b(?:htmlspecialchars|htmlentities|strip_tags)" + _ARGS, frozenset({"xss"})),
        (r"\b(?:escapeshellarg|escapeshellcmd)" + _ARGS, frozenset({"cmd"})),
        (r"\bbasename" + _ARGS, frozenset({"path", "lfi"})),
        (r"\b(?:urlencode|rawurlencode)" + _ARGS, _ENCODED),
        (r"\bmysqli_real_escape_string" + _ARGS + r"|\$\w+->(?:quote|real_escape_string)" + _ARGS,
         frozenset({"sql"})),
    ],
    "java": [
        (r"\b(?:Integer\.parseInt|Long\.parseLong|Integer\.valueOf|Long\.valueOf|UUID\.fromString)" + _ARGS, None),
        (r"\bURLEncoder\.encode" + _ARGS, _ENCODED),
        (r"\b(?:Encode\.forHtml\w*|HtmlUtils\.htmlEscape|StringEscapeUtils\.escapeHtml4)" + _ARGS,
         frozenset({"xss"})),
        (r"\bFilenameUtils\.getName" + _ARGS, frozenset({"path", "lfi"})),
    ],
    "csharp": [
        (r"\b(?:int\.Parse|long\.Parse|Guid\.Parse|Convert\.ToInt32|Convert\.ToInt64)" + _ARGS, None),
        (r"\b(?:HtmlEncoder\.Default\.Encode|WebUtility\.HtmlEncode|HttpUtility\.HtmlEncode)" + _ARGS,
         frozenset({"xss"})),
        (r"\bUri\.EscapeDataString" + _ARGS, _ENCODED),
        (r"\bPath\.GetFileName" + _ARGS, frozenset({"path", "lfi"})),
    ],
    "go": [
        (r"\bstrconv\.(?:Atoi|ParseInt|ParseUint|ParseFloat|ParseBool)" + _ARGS
         # sortie d'un programme lancé sans shell : produite par le programme, pas par le client
         + r"|exec\.Command(?:Context)?" + _ARGS + r"\.(?:Output|CombinedOutput)\(\)", None),
        (r"\b(?:html\.EscapeString|template\.HTMLEscapeString)" + _ARGS, frozenset({"xss"})),
        (r"\b(?:url\.PathEscape|url\.QueryEscape)" + _ARGS, _ENCODED),
        (r"\b(?:filepath\.Base|path\.Base)" + _ARGS, frozenset({"path", "lfi"})),
    ],
}
_SANITIZER_TABLE["typescript"] = _SANITIZER_TABLE["javascript"]
# Langage → type de faille → nettoyages efficaces contre cette faille
# Résultat d'une lecture (fichier, requête réseau, base de données, commande) : contenu produit par le
# serveur, pas par le client, même si l'argument de la lecture venait de lui
_RESULT_KINDS = {"sql", "cmd", "ssrf", "path", "lfi"}
# Contrôle de préfixe suivi d'une sortie : « if (!target.startsWith(BASE + path.sep)) return … » protège
# la variable contre la traversée de répertoire (groupe : nom de la variable)
_PREFIX_GUARDS = {
    "python": _r(r"\bif\s+not\s+(?:os\.path\.(?:realpath|abspath|normpath)\(\s*)?(\w+)\)?"
                 r"(?:\.resolve\(\))?\.(?:startswith|is_relative_to)\("),
    "javascript": _r(r"\bif\s*\(\s*!\s*(\w+)\.startsWith\("),
    "php": _r(r"\bif\s*\(\s*(?:strpos\(\s*\$(\w+)\s*,[^)]*\)\s*!==\s*0|!\s*str_starts_with\(\s*\$(\w+))"),
    "java": _r(r"\bif\s*\(\s*!\s*(\w+)(?:\.\w+\(\))*\.startsWith\("),
    "csharp": _r(r"\bif\s*\(\s*!\s*(\w+)(?:\.\w+\(\))*\.StartsWith\("),
    "go": _r(r"\bif\s+!strings\.HasPrefix\(\s*(\w+)\s*,"),
}
_PREFIX_GUARDS["typescript"] = _PREFIX_GUARDS["javascript"]
_EXIT = _r(r"\b(return|throw|raise|abort|exit|die|continue)\b|http\.Error\(|\bres\.status\(\s*4")

SANITIZERS_BY_KIND: dict[str, dict[str, re.Pattern]] = {
    language: {kind: _r("|".join(f"(?:{pattern})" for pattern, kinds in entries if kinds is None or kind in kinds))
               for kind in KINDS}
    for language, entries in _SANITIZER_TABLE.items()
}


def split_arguments(text: str) -> list[str]:
    """Arguments d'un appel, `text` commençant juste après la parenthèse ouvrante."""
    args, depth, quote, start = [], 0, "", 0
    for i, ch in enumerate(text):
        if quote:
            # guillemet non échappé : nombre pair d'antislashs juste avant (« "a\\" » se ferme)
            if ch == quote and (i - len(text[:i].rstrip("\\"))) % 2 == 0:
                quote = ""
        elif ch in "\"'`":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                args.append(text[start:i])
                return [a for a in args if a.strip()]
            depth -= 1
        elif ch == "," and depth == 0:
            args.append(text[start:i])
            start = i + 1
    args.append(text[start:])
    return [a for a in args if a.strip()]


def _first_argument(text: str) -> str:
    """Premier argument d'un appel, `text` commençant juste après la parenthèse ouvrante."""
    args = split_arguments(text)
    return args[0] if args else ""


def _names(target: str, language: str) -> list[str]:
    if language in JS and target[:1] in "{[":
        # Déstructuration : const { url, id: identifiant } = req.query
        parts = [p.split(":")[-1].split("=")[0].strip().lstrip(".") for p in target.strip("{}[]").split(",")]
        return [p for p in parts if re.fullmatch(r"[A-Za-z_$][\w$]*", p)]
    return [n.strip() for n in target.split(",") if n.strip()]



# ---------------------------------------------------------------------- instructions sur plusieurs lignes
# Code formaté (black, prettier…) : « cur.execute(\n    "SELECT …" + uid\n) ». Les lignes d'une même
# instruction (parenthèse ou crochet encore ouvert) sont regroupées ; on s'arrête à l'ouverture d'un bloc
# (« ) { », « => { », « : » en Python), sinon tout le corps d'un callback serait aspiré.
MAX_JOINED_LINES = 25
_BLOCK_START = _r(r"(\)|=>|\belse|\btry|\bdo|\bfinally)\s*\{\s*$|:\s*$")


def _depth(line: str) -> int:
    depth, quote, i = 0, "", 0
    while i < len(line):
        c = line[i]
        if quote:
            if c == "\\":
                i += 1
            elif c == quote:
                quote = ""
        elif c in "\"'`":
            quote = c
        elif c in "([":
            depth += 1
        elif c in ")]":
            depth -= 1
        elif c == "#" or line.startswith("//", i):
            break  # commentaire de fin de ligne
        i += 1
    return depth


# Hors Python : instruction coupée après un opérateur (« String q = », « … + ») ou avant (« + name »)
_ENDS_WITH_OPERATOR = _r(r"(?<![=!<>])=\s*$|(?<!\+)\+\s*$|\|\|\s*$|&&\s*$|(?<=[\s'\"\)])\.\s*$")
_STARTS_WITH_OPERATOR = _r(r"^\s*(\+(?!\+)|\|\||&&|\.\s)")


def _continues(lines: list[str], i: int, language: str | None) -> bool:
    if language in (None, "python") or i + 1 >= len(lines):
        return False
    return bool(_ENDS_WITH_OPERATOR.search(lines[i]) or _STARTS_WITH_OPERATOR.match(lines[i + 1]))


def logical_lines(lines: list[str], language: str | None = None):
    """(index de la première ligne, index de la dernière, texte de l'instruction complète)."""
    i, n = 0, len(lines)
    while i < n:
        start, text, depth = i, lines[i], _depth(lines[i])
        while ((depth > 0 or lines[i].rstrip().endswith("\\") or _continues(lines, i, language))
               and i + 1 < n and i - start < MAX_JOINED_LINES
               and not _BLOCK_START.search(lines[i]) and len(text) < MAX_LINE_LENGTH):
            i += 1
            text = text.rstrip().rstrip("\\") + " " + lines[i].strip()
            depth += _depth(lines[i])
        yield start, i, text
        i += 1


# Échappement SQL : ne protège que si la valeur est ensuite placée entre guillemets dans la requête
# (« WHERE id = '$id' ») ; « WHERE id = $id » reste injectable (« 1 OR 1=1 » n'a aucun guillemet à échapper).
# PDO::quote ajoute lui-même les guillemets : il n'en fait pas partie.
_SQL_ESCAPE_CALL = {"php": _r(r"\b(?:mysqli_real_escape_string|mysql_real_escape_string)\s*\(|->real_escape_string\s*\(")}


class _Tainted:
    def __init__(self, language: str):
        self.language = language
        self.vars: dict[str, int] = {}  # nom → ligne où la donnée non fiable a été reçue
        # nom → failles contre lesquelles la valeur n'a pas été nettoyée (absent : toutes)
        self.kinds: dict[str, frozenset] = {}
        self.assigned: dict[str, int] = {}  # nom → dernière ligne où la variable a été construite
        # Valeurs échappées pour SQL : sûres dans une requête seulement entre guillemets
        self.escaped: set[str] = set()
        self._patterns: dict[str, re.Pattern] = {}

    def _pattern(self, name: str) -> re.Pattern:
        if name not in self._patterns:
            if self.language == "php":
                self._patterns[name] = re.compile(r"\$" + re.escape(name) + r"\b")
            else:  # le nom seul, pas un appel « name( », un attribut « .name » ni une clé « name: »
                self._patterns[name] = re.compile(r"(?<![\w$.])" + re.escape(name) + r"\b(?!\s*\()")
        return self._patterns[name]

    def _mentions(self, name: str, expr: str) -> bool:
        """La variable apparaît comme valeur : pas comme appel « name( », attribut « .name » ni clé d'objet
        « { name: … } » (mais bien dans un ternaire « ok ? name : défaut »)."""
        for m in self._pattern(name).finditer(expr):
            if self.language != "php" and re.match(r"\s*:(?!:)", expr[m.end():]):
                before = expr[:m.start()].rstrip()
                if not before or before[-1] in "{,":
                    continue
            return True
        return False

    def first_hit(self, expr: str, line_no: int, kind: str | None = None) -> tuple[str, int] | None:
        """(variable ou « entrée utilisateur », ligne d'origine) si l'expression porte une donnée non fiable
        pour la faille `kind` (None : pour au moins une faille)."""
        if kind is None:
            return next((hit for k in KINDS if (hit := self.first_hit(expr, line_no, k))), None)
        sanitizers = SANITIZERS_BY_KIND[self.language][kind]
        previous = None
        while previous != expr:  # nettoyages imbriqués : int(escape(x))
            previous, expr = expr, sanitizers.sub("0", expr)
        if SOURCES[self.language].search(expr):
            return ("entrée utilisateur", line_no)
        raw = expr
        expr = _strip_plain_strings(_PLAIN_STRINGS[self.language], expr)
        for name, origin in self.vars.items():
            if kind in self.kinds.get(name, ALL_KINDS) and self._mentions(name, expr):
                return (name, origin)
        if kind == "sql":
            for name in self.escaped:
                if name in self.vars and self._unquoted(name, raw):
                    return (name, self.vars[name])
        return None

    def _unquoted(self, name: str, expr: str) -> bool:
        """Une occurrence de la variable n'est pas entre apostrophes (« = $id » et non « = '$id' »)."""
        for m in self._pattern(name).finditer(expr):
            before = expr[:m.start()].rstrip("{")
            after = expr[m.end():].lstrip("}")
            if not (before.endswith("'") and after.startswith("'")):
                return True
        return False

    def escapes_for_sql(self, expr: str, line_no: int) -> bool:
        """L'expression échappe pour SQL une donnée non fiable (mysqli_real_escape_string($c, $id))."""
        pattern = _SQL_ESCAPE_CALL.get(self.language)
        if not pattern:
            return False
        for m in pattern.finditer(expr):
            args = split_arguments(expr[m.end():])
            if args and self.first_hit(args[-1], line_no):  # valeur échappée : dernier argument
                return True
        return False

    def still_tainted(self, expr: str, line_no: int) -> tuple[tuple[str, int] | None, frozenset]:
        """Pour une affectation : première origine non fiable, et failles pour lesquelles elle le reste."""
        hits = {k: hit for k in KINDS if (hit := self.first_hit(expr, line_no, k))}
        first = next(iter(hits.values()), None)
        return first, frozenset(hits)


def find_flows(source: SourceFile, initial: dict[str, int] | None = None, first_line: int = 1,
               summaries: dict[str, list[ParamSink]] | None = None,
               call_hits: list[CallHit] | None = None) -> list[FlowFinding]:
    """Flux du fichier. Pour un corps de fonction (flux entre fichiers) : `initial` = paramètres déjà
    teintés, `first_line` = numéro de sa première ligne ; `summaries` + `call_hits` : appels de
    fonctions résumées qui reçoivent une donnée non fiable."""
    language = source.language
    if language not in SINKS:
        return []
    tainted = _Tainted(language)
    tainted.vars.update(initial or {})
    findings: list[FlowFinding] = []
    controller = language == "csharp" and bool(_CS_CONTROLLER.search(source.content))
    # Portées ouvertes : (indentation, variables suivies juste avant cette fonction)
    scopes: list[tuple[int, dict, dict]] = []
    lines = source.content.split("\n")
    for start, end, line in logical_lines(lines, language):
        idx = first_line + start
        if not line.strip() or _COMMENT.match(line) or len(line) > MAX_LINE_LENGTH:
            continue
        defined = None
        if _FUNCTION_START[language].search(line):
            defined = (m.group(1) if (m := _DEFINED_NAME.search(line)) else None)
            indent = len(line) - len(line.lstrip())
            # Une fonction imbriquée (callback, closure) voit les variables de la fonction qui l'entoure. Une
            # fonction voisine repart de l'état de la fonction englobante, pas de celui de sa voisine ; une
            # fonction de premier niveau repart de zéro (ou des paramètres suivis, pour un corps résumé)
            while scopes and scopes[-1][0] >= indent:
                _, saved_vars, saved_kinds = scopes.pop()
                tainted.vars, tainted.kinds = dict(saved_vars), dict(saved_kinds)
            if not scopes and initial is None:
                tainted.vars.clear()
                tainted.kinds.clear()
            scopes.append((indent, dict(tainted.vars), dict(tainted.kinds)))
            if language == "java":
                for m in _ANNOTATED_PARAM.finditer(line):
                    tainted.vars[m.group(4)] = idx
                # Méthode d'un contrôleur Spring (@PostMapping…) : ses paramètres texte sans annotation sont
                # aussi remplis à partir de la requête
                if any(_SPRING_MAPPING.search(previous) for previous in lines[max(0, start - 4):start]):
                    for m in _SPRING_TEXT_PARAM.finditer(line.split("(", 1)[-1]):
                        tainted.vars[m.group(1)] = idx
            if controller and (action := _CS_ACTION.match(line)):
                for m in _CS_TEXT_PARAM.finditer(action.group(3)):
                    tainted.vars[m.group(3)] = idx
        flagged = False
        for sink in SINKS[language]:
            m = sink.pattern.search(line)
            if not m:
                continue
            expr = _first_argument(line[m.end():]) if sink.first_arg else line[m.start():]
            if hit := tainted.first_hit(expr, idx, sink.kind):
                findings.append(FlowFinding(sink.rule_id, sink.kind, idx, hit[0], hit[1],
                                            tainted.assigned.get(hit[0], 0)))
                flagged = True
                break  # une alerte de flux par ligne
        if summaries and call_hits is not None:
            for call in _CALL.finditer(line):
                if call.group(1) == defined:
                    continue
                for param_sink in summaries.get(call.group(1), ()):
                    args = split_arguments(line[call.end():])
                    if param_sink.param < len(args) and (
                            hit := tainted.first_hit(args[param_sink.param], idx, param_sink.kind)):
                        call_hits.append(CallHit(param_sink, idx, hit[0], hit[1]))
        if assign := ASSIGN[language].match(line):
            # Résultat d'une opération déjà signalée (sortie de la commande…) : pas d'alerte en cascade
            rhs = assign.group(2)
            # (« r.URL.Query() » en Go lit l'entrée utilisateur : ce n'est pas le résultat d'une requête SQL)
            reads = not SOURCES[language].search(rhs) and any(
                s.kind in _RESULT_KINDS and s.pattern.search(rhs) for s in SINKS[language])
            safe = flagged or reads or _ALLOWLIST.search(assign.group(2))
            hit, kinds = (None, frozenset()) if safe else tainted.still_tainted(assign.group(2), idx)
            escaped = bool(hit) and "sql" not in kinds and tainted.escapes_for_sql(assign.group(2), idx)
            augmented = "+=" in line or ".=" in line
            for name in _names(assign.group(1), language):
                if hit:
                    tainted.vars.setdefault(name, hit[1])
                    tainted.assigned[name] = idx
                    # « $q .= $x » : la valeur cumule les failles possibles de ses morceaux
                    previous = tainted.kinds.get(name, ALL_KINDS) if augmented and name in tainted.vars else frozenset()
                    tainted.kinds[name] = kinds | previous
                    if escaped:
                        tainted.escaped.add(name)
                    elif not augmented:
                        tainted.escaped.discard(name)
                elif not augmented:
                    tainted.vars.pop(name, None)  # réaffectée avec une valeur sûre
                    tainted.kinds.pop(name, None)
                    tainted.escaped.discard(name)
        if (guard := _PREFIX_GUARDS[language].search(line)) and (
                _EXIT.search(line[guard.end():]) or _EXIT.search(_next_code_line(lines, end))):
            name = next(g for g in guard.groups() if g)
            if name in tainted.vars:
                tainted.kinds[name] = tainted.kinds.get(name, ALL_KINDS) - {"path", "lfi"}
    return findings


def _next_code_line(lines: list[str], index: int) -> str:
    return next((line for line in lines[index + 1:index + 3] if line.strip()), "")


def describe(flow: FlowFinding) -> str:
    title = KINDS[flow.kind][0].lower()
    if flow.variable == "entrée utilisateur":
        return f"Une entrée utilisateur arrive sans nettoyage dans une opération sensible : risque de {title}."
    return (f"La variable « {flow.variable} » porte une entrée utilisateur reçue ligne {flow.source_line} et "
            f"arrive sans nettoyage dans une opération sensible : risque de {title}.")
