"""Suivi des données d'un fichier à l'autre (analyse interprocédurale simplifiée).

Dans un vrai projet, la route qui lit l'entrée utilisateur et l'opération dangereuse sont souvent dans
des fichiers différents : `routes.py` appelle `storage.load_attachment(name)`, qui fait `open(...)`.

1. Résumés : chaque fonction du projet est analysée avec ses paramètres considérés comme non fiables
   (taint.py) ; on retient « le paramètre n atteint telle opération dangereuse, à telle ligne ».
2. Propagation : une fonction qui passe son paramètre à une fonction résumée hérite du résumé
   (A → B → C), jusqu'à stabilité.
3. Appels : partout dans le projet, un appel à une fonction résumée avec une entrée utilisateur à la
   bonne position produit une alerte à l'endroit de l'opération dangereuse, qui cite l'appelant.

Pour limiter les confusions entre fonctions homonymes, seuls les noms définis une seule fois dans le
projet (par famille de langages) et assez distinctifs sont suivis.
"""
import re
from dataclasses import dataclass

from ..ingest import SourceFile
from .taint import KINDS, SINKS, CallHit, ParamSink, find_flows, split_arguments

MAX_ROUNDS = 4
# Noms trop courants pour être reliés sans ambiguïté à une définition précise
_GENERIC = {
    "get", "set", "run", "read", "write", "send", "query", "execute", "open", "close", "main", "init", "handle",
    "process", "update", "delete", "create", "find", "save", "load", "render", "request", "call", "apply", "bind",
    "push", "map", "filter", "join", "split", "format", "print", "log", "fetch", "start", "stop", "parse", "test",
    "index", "show", "list", "post", "put", "patch", "next", "then", "catch", "append", "remove", "insert", "select",
}
_KEYWORDS = {"if", "for", "while", "switch", "catch", "return", "function", "elif", "with", "foreach", "sizeof"}

_DEFS = {
    "python": [re.compile(r"^(\s*)(?:async\s+)?def\s+(\w+)\s*\((.*)\)\s*(?:->[^:]+)?:")],
    "javascript": [
        re.compile(r"^(\s*)(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s*\*?\s*(\w+)\s*\(([^)]*)\)"),
        re.compile(r"^(\s*)(?:export\s+)?(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:function\s*)?\(([^)]*)\)"),
        re.compile(r"^(\s*)(?:static\s+)?(?:async\s+)?(\w+)\s*\(([^)]*)\)\s*\{"),  # méthode de classe
    ],
    "php": [re.compile(r"^(\s*)(?:(?:public|private|protected|static|final)\s+)*function\s+(\w+)\s*\(([^)]*)\)")],
    "java": [re.compile(r"^(\s*)(?:(?:public|private|protected|static|final|synchronized|abstract)\s+)+"
                        r"[\w<>\[\],.? ]+\s+(\w+)\s*\(([^)]*)\)")],
    "csharp": [re.compile(r"^(\s*)(?:(?:public|private|protected|internal|static|async|virtual|override|sealed)\s+)+"
                          r"[\w<>\[\],.? ]+\s+(\w+)\s*\(([^)]*)\)")],
    "go": [re.compile(r"^()func\s+(?:\([^)]*\)\s*)?(\w+)\s*\(([^)]*)\)")],
}
_DEFS["typescript"] = _DEFS["javascript"]
_FAMILY = {"typescript": "javascript"}


@dataclass
class Function:
    name: str
    params: list[str | None]  # None : paramètre non suivi (déstructuration…)
    source: SourceFile
    first_line: int  # première ligne du corps
    body: str


def _param_names(raw: str, language: str) -> list[str | None]:
    names: list[str | None] = []
    for part in split_arguments(raw + ")") if raw.strip() else []:
        part = part.strip()
        if language == "php":
            m = re.search(r"\$(\w+)", part)
        elif language == "python":
            m = re.match(r"\**(\w+)", part)
        elif language in ("javascript", "typescript"):
            m = re.match(r"(?:\.\.\.)?([A-Za-z_$][\w$]*)", part)
        elif language == "go":
            m = re.match(r"(\w+)", part)
        else:  # Java, C# : « [@Annotation] [final] Type nom [= défaut] »
            m = re.search(r"(\w+)\s*(?:=[^,]*)?$", part)
        name = m.group(1) if m else None
        if language == "python" and name in ("self", "cls") and not names:
            continue  # l'objet de l'appel n'est pas un argument écrit
        names.append(name)
    return names


def _body(lines: list[str], start: int, indent: str, language: str) -> tuple[int, list[str]]:
    """(numéro de la première ligne du corps, lignes du corps) ; `start` : index de la ligne de définition."""
    if language == "python":
        body = []
        for line in lines[start + 1:]:
            if line.strip() and len(line) - len(line.lstrip()) <= len(indent):
                break
            body.append(line)
        return start + 2, body
    depth, opened = 0, False
    for end in range(start, len(lines)):
        depth += lines[end].count("{") - lines[end].count("}")
        opened = opened or "{" in lines[end]
        if opened and depth <= 0:
            return start + 2, lines[start + 1:end + 1]
    return start + 2, lines[start + 1:]


def extract_functions(source: SourceFile) -> list[Function]:
    lines = source.content.split("\n")
    out = []
    for idx, line in enumerate(lines):
        for pattern in _DEFS.get(source.language, ()):
            m = pattern.match(line)
            if not m or m.group(2) in _KEYWORDS:
                continue
            first_line, body = _body(lines, idx, m.group(1), source.language)
            out.append(Function(m.group(2), _param_names(m.group(3), source.language), source, first_line,
                                "\n".join(body)))
            break
    return out


@dataclass(frozen=True)
class CrossFlow:
    """Alerte à placer sur l'opération dangereuse (fichier appelé), avec l'origine (appelant)."""
    sink: ParamSink
    caller_file: str
    caller_line: int
    variable: str
    source_line: int


def _trackable(functions: list[Function]) -> dict[tuple[str, str], Function]:
    by_name: dict[tuple[str, str], list[Function]] = {}
    for f in functions:
        family = _FAMILY.get(f.source.language, f.source.language)
        by_name.setdefault((family, f.name), []).append(f)
    return {key: defs[0] for key, defs in by_name.items()
            if len(defs) == 1 and len(key[1]) >= 4 and key[1].lower() not in _GENERIC}


def cross_file_flows(code_files: list[SourceFile]) -> list[CrossFlow]:
    files = [s for s in code_files if s.language in SINKS]
    functions = _trackable([f for s in files for f in extract_functions(s)])
    summaries: dict[str, dict[str, list[ParamSink]]] = {}  # famille → nom → résumés

    def table(language: str) -> dict[str, list[ParamSink]]:
        return summaries.setdefault(_FAMILY.get(language, language), {})

    # 1-2. Résumés, propagés jusqu'à stabilité (A → B → C)
    for _ in range(MAX_ROUNDS):
        changed = False
        for (_family, name), fn in functions.items():
            initial = {p: -(i + 1) for i, p in enumerate(fn.params) if p}
            if not initial:
                continue
            body = SourceFile(fn.source.path, fn.source.language, fn.body)
            hits: list[CallHit] = []
            flows = find_flows(body, initial=initial, first_line=fn.first_line,
                               summaries=table(fn.source.language), call_hits=hits)
            found = [ParamSink(-f.source_line - 1, f.rule_id, f.kind, fn.source.path, f.line, name)
                     for f in flows if f.source_line < 0]
            found += [ParamSink(-h.origin - 1, h.sink.rule_id, h.sink.kind, h.sink.file, h.sink.line, name)
                      for h in hits if h.origin < 0 and h.sink.function != name]
            current = table(fn.source.language).setdefault(name, [])
            for sink in found:
                if sink not in current:
                    current.append(sink)
                    changed = True
        if not changed:
            break

    # 3. Appels qui transmettent une entrée utilisateur
    results: dict[tuple[str, int, str], CrossFlow] = {}
    for source in files:
        hits = []
        find_flows(source, summaries=table(source.language), call_hits=hits)
        for h in hits:
            if h.origin > 0:
                results.setdefault((h.sink.file, h.sink.line, h.sink.kind),
                                   CrossFlow(h.sink, source.path, h.line, h.variable, h.origin))
    return list(results.values())


def describe(flow: CrossFlow) -> str:
    title = KINDS[flow.sink.kind][0].lower()
    origin = ("une entrée utilisateur" if flow.variable == "entrée utilisateur"
              else f"la variable « {flow.variable} », qui porte une entrée utilisateur")
    return (f"{flow.sink.function}() reçoit {origin} depuis {flow.caller_file} (ligne {flow.caller_line}) "
            f"et la transmet sans nettoyage à une opération sensible : risque de {title}.")
