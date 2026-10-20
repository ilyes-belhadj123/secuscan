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


_CALL = re.compile(r"([A-Za-z_$][\w$]*)\s*\(")


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
              r"escapeshellcmd|basename|urlencode|rawurlencode|filter_var|mysqli_real_escape_string)\((?:[^()]|\([^()]*\))*\)"
              r"|\$\w+->(quote|real_escape_string)\((?:[^()]|\([^()]*\))*\)|\(int\)\s*\$\w+"),
    "java": _r(r"\b(Integer\.parseInt|Long\.parseLong|Integer\.valueOf|Long\.valueOf|UUID\.fromString|"
               r"URLEncoder\.encode|Encode\.forHtml\w*|HtmlUtils\.htmlEscape|StringEscapeUtils\.escapeHtml4|"
               r"FilenameUtils\.getName)\((?:[^()]|\([^()]*\))*\)"),
}

# Affectations : groupe 1 = nom(s) affecté(s), groupe 2 = expression
ASSIGN = {
    "python": _r(r"^\s*([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s*(?::\s*[\w\[\], .|]+)?\s*\+?=(?!=)\s*(.+)$"),
    "javascript": _r(r"^\s*(?:const|let|var)?\s*(\{[^}]*\}|\[[^\]]*\]|[A-Za-z_$][\w$]*)\s*(?::\s*[\w<>\[\]|]+)?"
                     r"\s*\+?=(?![=>])\s*(.+)$"),
    "php": _r(r"^\s*\$(\w+)\s*\.?=(?![=>])\s*(.+)$"),
    "java": _r(r"^\s*(?:final\s+)?(?:[\w.<>\[\], ?]+\s+)?([A-Za-z_]\w*)\s*\+?=(?!=)\s*(.+)$"),
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
                                   r"|\bhttps?\.(get|request)\(")),
        Sink("JS-PATH-FLOW", "path", _r(r"\bfs\.(readFile|readFileSync|createReadStream|writeFile|unlink)\w*\("
                                        r"|\bres\.(sendFile|download)\(")),
        Sink("JS-REDIRECT-FLOW", "redirect", _r(r"\bres\.redirect\(|\blocation\.(assign|replace)\(")),
        Sink("JS-XSS-FLOW", "xss", _r(r"\bres\.(send|write|end)\(|\.(innerHTML|outerHTML)\s*=|document\.write\("
                                      r"|insertAdjacentHTML\("), first_arg=False),
    ],
    "php": [
        Sink("PHP-SQLI-FLOW", "sql", _r(r"\b(mysqli_query|pg_query)\(\s*\$\w+\s*,|->(query|exec|multi_query)\(")),
        Sink("PHP-CMDI-FLOW", "cmd", _r(r"(?<![$\w>])(system|exec|shell_exec|passthru|popen|proc_open)\(")),
        Sink("PHP-SSRF", "ssrf", _r(r"(?<![$\w>])(file_get_contents|curl_init|fopen|get_headers)\(")),
        Sink("PHP-LFI-FLOW", "lfi", _r(r"(?<![$\w>])(include|include_once|require|require_once)\b\s*\(?"),
             first_arg=False),
        Sink("PHP-PATH-FLOW", "path", _r(r"(?<![$\w>])(readfile|unlink|file)\(")),
        Sink("PHP-REDIRECT-FLOW", "redirect", _r(r"\bheader\(\s*[\"']Location:"), first_arg=False),
        Sink("PHP-XSS-FLOW", "xss", _r(r"^\s*(echo|print)\b|<\?=|\bprintf\("), first_arg=False),
    ],
    "java": [
        Sink("JAVA-SQLI-FLOW", "sql", _r(r"\.(executeQuery|executeUpdate|execute|addBatch|prepareStatement|"
                                         r"createQuery|createNativeQuery)\(")),
        Sink("JAVA-CMDI-FLOW", "cmd", _r(r"\.exec\(|new\s+ProcessBuilder\(")),
        Sink("JAVA-SSRF", "ssrf", _r(r"new\s+URL\(|URI\.create\(|\.(getForObject|getForEntity)\(")),
        Sink("JAVA-PATH-FLOW", "path", _r(r"new\s+(File|FileInputStream|FileReader|FileOutputStream)\(|Paths\.get\(")),
        Sink("JAVA-REDIRECT-FLOW", "redirect", _r(r"\.sendRedirect\(")),
        Sink("JAVA-XSS-FLOW", "xss", _r(r"\.getWriter\(\)\.(print|println|write)\("), first_arg=False),
    ],
}

# Chaînes sans interpolation, retirées avant de chercher des noms de variables (« name » dans un texte)
_PLAIN_STRINGS = {
    "python": _r(r"(?<![fF\w])(\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*')"),
    "javascript": _r(r"\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*'"),
    "php": _r(r"'(?:[^'\\]|\\.)*'"),  # les guillemets doubles interpolent les variables
    "java": _r(r"\"(?:[^\"\\]|\\.)*\""),
}
# Début d'une fonction ou d'une route : les variables suivies repartent de zéro
_FUNCTION_START = {
    "python": _r(r"^\s*(async\s+)?def\s"),
    "javascript": _r(r"\bfunction\b[^(]*\(|=>\s*\{\s*$"),
    "php": _r(r"\bfunction\s+\w+\s*\("),
    "java": _r(r"^(?!\s*(try|if|for|while|switch|catch|synchronized|return|else|do|new)\b)"
               r"\s*(public|private|protected|static|final|synchronized|\s)*[\w<>\[\], ?]+\s+\w+\s*\([^;]*\)\s*"
               r"(throws\s+[\w., ]+)?\s*\{?\s*$"),
}
# Paramètres reçus du client par annotation (Spring) : teintés dès la signature
_ANNOTATED_PARAM = _r(r"@(RequestParam|PathVariable|RequestBody|RequestHeader)(\([^)]*\))?\s+(final\s+)?"
                      r"[\w<>\[\]]+\s+(\w+)")
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
ASSIGN["csharp"] = _r(r"^\s*(?:using\s+)?(?:var|[\w.<>\[\]?]+)?\s*([A-Za-z_]\w*)\s*\+?=(?![=>])\s*(.+)$")
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
    Sink("CS-XSS-FLOW", "xss", _r(r"(?<![\w.])Content\(|\bHtml\.Raw\(|\.Response\.WriteAsync\(")),
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
_PLAIN_STRINGS["csharp"] = _r(r"(?<![$\w])@?\"(?:[^\"\\]|\\.)*\"")  # $"…" interpole, les autres non
_PLAIN_STRINGS["go"] = _r(r"\"(?:[^\"\\]|\\.)*\"|`[^`]*`")
_FUNCTION_START["csharp"] = _r(r"^(?!\s*(try|if|for|foreach|while|switch|catch|using|lock|return)\b)"
                               r"\s*(public|private|protected|internal)\s+(static\s+|async\s+|virtual\s+|override\s+)*"
                               r"[\w<>\[\], ?]+\s+\w+\s*\(")
_FUNCTION_START["go"] = _r(r"^\s*func\b")
# ASP.NET : les paramètres texte d'une action de contrôleur sont remplis à partir de la requête
_CS_CONTROLLER = _r(r":\s*(Controller|ControllerBase)\b|\[ApiController\]")
_CS_ACTION = _r(r"^\s*public\s+(async\s+)?(virtual\s+)?[\w<>\[\], ?]+\s+\w+\s*\(([^)]*)\)")
_CS_TEXT_PARAM = _r(r"(\[From\w+[^\]]*\]\s*)?\b(string|object|dynamic|IFormFile|JsonElement)\??\s+(\w+)")

_COMMENT = _r(r"^\s*(#|//|/?\*)")
for table in (SOURCES, SANITIZERS, ASSIGN, SINKS, _PLAIN_STRINGS, _FUNCTION_START):
    table["typescript"] = table["javascript"]


def split_arguments(text: str) -> list[str]:
    """Arguments d'un appel, `text` commençant juste après la parenthèse ouvrante."""
    args, depth, quote, start = [], 0, "", 0
    for i, ch in enumerate(text):
        if quote:
            if ch == quote and text[i - 1] != "\\":
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


class _Tainted:
    def __init__(self, language: str):
        self.language = language
        self.vars: dict[str, int] = {}  # nom → ligne où la donnée non fiable a été reçue
        self.assigned: dict[str, int] = {}  # nom → dernière ligne où la variable a été construite
        self._patterns: dict[str, re.Pattern] = {}

    def _pattern(self, name: str) -> re.Pattern:
        if name not in self._patterns:
            if self.language == "php":
                self._patterns[name] = re.compile(r"\$" + re.escape(name) + r"\b")
            else:  # le nom seul, pas un appel « name( », un attribut « .name » ni une clé « name: »
                self._patterns[name] = re.compile(r"(?<![\w$.])" + re.escape(name) + r"\b(?!\s*[(:])")
        return self._patterns[name]

    def first_hit(self, expr: str, line_no: int) -> tuple[str, int] | None:
        """(variable ou « entrée utilisateur », ligne d'origine) si l'expression porte une donnée non fiable."""
        previous = None
        while previous != expr:  # nettoyages imbriqués : int(escape(x))
            previous, expr = expr, SANITIZERS[self.language].sub("0", expr)
        if SOURCES[self.language].search(expr):
            return ("entrée utilisateur", line_no)
        expr = _PLAIN_STRINGS[self.language].sub('""', expr)
        for name, origin in self.vars.items():
            if self._pattern(name).search(expr):
                return (name, origin)
        return None


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
    for idx, line in enumerate(source.content.split("\n"), start=first_line):
        if not line.strip() or _COMMENT.match(line):
            continue
        if _FUNCTION_START[language].search(line):
            tainted.vars.clear()
            if language == "java":
                for m in _ANNOTATED_PARAM.finditer(line):
                    tainted.vars[m.group(4)] = idx
            if controller and (action := _CS_ACTION.match(line)):
                for m in _CS_TEXT_PARAM.finditer(action.group(3)):
                    tainted.vars[m.group(3)] = idx
        flagged = False
        for sink in SINKS[language]:
            m = sink.pattern.search(line)
            if not m:
                continue
            expr = _first_argument(line[m.end():]) if sink.first_arg else line[m.start():]
            if hit := tainted.first_hit(expr, idx):
                findings.append(FlowFinding(sink.rule_id, sink.kind, idx, hit[0], hit[1],
                                            tainted.assigned.get(hit[0], 0)))
                flagged = True
                break  # une alerte de flux par ligne
        if summaries and call_hits is not None:
            for call in _CALL.finditer(line):
                for param_sink in summaries.get(call.group(1), ()):
                    args = split_arguments(line[call.end():])
                    if param_sink.param < len(args) and (hit := tainted.first_hit(args[param_sink.param], idx)):
                        call_hits.append(CallHit(param_sink, idx, hit[0], hit[1]))
        if assign := ASSIGN[language].match(line):
            # Résultat d'une opération déjà signalée (sortie de la commande…) : pas d'alerte en cascade
            safe = flagged or _ALLOWLIST.search(assign.group(2))
            hit = None if safe else tainted.first_hit(assign.group(2), idx)
            augmented = "+=" in line or ".=" in line
            for name in _names(assign.group(1), language):
                if hit:
                    tainted.vars.setdefault(name, hit[1])
                    tainted.assigned[name] = idx
                elif not augmented:
                    tainted.vars.pop(name, None)  # réaffectée avec une valeur sûre
    return findings


def describe(flow: FlowFinding) -> str:
    title = KINDS[flow.kind][0].lower()
    if flow.variable == "entrée utilisateur":
        return f"Une entrée utilisateur arrive sans nettoyage dans une opération sensible : risque de {title}."
    return (f"La variable « {flow.variable} » porte une entrée utilisateur reçue ligne {flow.source_line} et "
            f"arrive sans nettoyage dans une opération sensible : risque de {title}.")
