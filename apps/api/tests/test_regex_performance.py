"""Aucune expression régulière du moteur ne doit s'emballer sur une ligne piégée (retour arrière
catastrophique) : un dépôt hostile pourrait sinon bloquer un worker pendant des minutes."""
import re
import time

from secuscan.analyzers import interproc, rules, sast, taint
from secuscan.analyzers.iac import IAC_RULES
from secuscan.ingest import SourceFile

LENGTH = taint.MAX_LINE_LENGTH - 100  # les lignes plus longues ne sont pas analysées
PIECES = [" ", "a", "a ", "public ", "x:", "$a", "(", "a(", "'", '"', "\\", "/", "*", "<", "a<b, ", ",", ".", "=",
          "+", "a.", "${", "{", "[", "@", "-", "\t", "%s", "SELECT ", "a=", "a,", "0", "a b"]


def _cases() -> list[str]:
    out = []
    for piece in PIECES:
        body = piece * (LENGTH // len(piece))
        out += [body, "x" + body, body + "!", "def f(" + body, "x = " + body, "public " + body + "(", "eval(" + body]
    return out


def _patterns() -> list[tuple[str, re.Pattern]]:
    found = []
    for rule in rules.RULES + list(IAC_RULES):
        found += [(rule.id, p) for p in (rule.pattern, rule.context_requires, rule.line_excludes) if p]
    for language, sinks in taint.SINKS.items():
        found += [(f"{language}:{s.rule_id}", s.pattern) for s in sinks]
    for table in ("SOURCES", "SANITIZERS", "ASSIGN", "_FUNCTION_START", "_PLAIN_STRINGS"):
        found += [(f"{table}:{k}", v) for k, v in getattr(taint, table).items()]
    for module in (taint, sast):
        found += [(name, obj) for name, obj in vars(module).items() if isinstance(obj, re.Pattern)]
    for language, defs in interproc._DEFS.items():
        found += [(f"def:{language}", d) for d in defs]
    return found


def test_no_regex_backtracks_on_hostile_lines():
    # Un retour arrière catastrophique se compte en secondes ; 0,25 s laisse de la marge à une machine chargée,
    # et un dépassement est remesuré avant d'être retenu
    def elapsed(pattern: re.Pattern, case: str) -> float:
        start = time.perf_counter()
        pattern.search(case)
        return time.perf_counter() - start

    slow = []
    cases = _cases()
    for name, pattern in _patterns():
        for case in cases:
            if elapsed(pattern, case) > 0.25 and (again := elapsed(pattern, case)) > 0.25:
                slow.append((name, repr(case[:15]), round(again, 2)))
    assert not slow, slow


def test_hostile_file_is_analysed_quickly():
    hostile = "\n".join(["else:" + " " * 1900, "public " * 280 + "(", "x" * 5000] * 20)
    start = time.perf_counter()
    for language in ("python", "java", "csharp", "javascript", "php"):
        sast.analyze_file(SourceFile("a", language, hostile))
    assert time.perf_counter() - start < 5


def test_assignment_names_are_captured_whole():
    js = taint.ASSIGN["javascript"].match("letter = req.query.u")
    assert js and js.group(1) == "letter"
    cs = taint.ASSIGN["csharp"].match('query = Request.Query["x"];')
    assert cs and cs.group(1) == "query"
    generic = taint.ASSIGN["java"].match("Map<String, List<Integer>> index = build(x);")
    assert generic and generic.group(1) == "index"
    typed = taint.ASSIGN["python"].match("user_id: int = request.args['id']")
    assert typed and typed.group(1) == "user_id"
