"""SS-4 — analyse statique isolée : lecture du code, secrets, règles, moteurs externes, manifestes.

C'est la seule étape qui lit le code importé, avec des analyseurs (tree-sitter, Bandit, YAML, XML)
qui pourraient avoir des failles. Elle ne demande ni réseau ni secret : l'IA et la base OSV
interviennent après, hors de la frontière. Trois modes (SECUSCAN_SANDBOX) :

- `inline` (défaut) : dans le processus de l'application, comme avant ;
- `process` : sous-processus Python sans variables d'environnement (clé IA, SMTP, OAuth…), sans
  lecture des fichiers .env, avec limites de mémoire et de temps (Linux) ;
- `container` : conteneur dédié (docker-compose : service `sandbox`) sans réseau, système de
  fichiers en lecture seule, sans privilèges, qui ne voit que le dossier des analyses. Échange par
  fichiers : `<id>.request.json` déposé par le worker, `<id>.result.json` rendu par le conteneur ;
- `ephemeral` : un conteneur neuf par analyse, détruit ensuite, qui ne voit que le dossier de cette
  analyse (voir sandbox_docker.py).

Le code analysé n'est jamais exécuté, dans aucun mode.
"""
import argparse
import hashlib
import json
import logging
import os
import re
import subprocess
import sys
import time
import uuid
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .analyzers import external, history, interproc, sast, sca, secrets
from .analyzers.context import enclosing_excerpt
from .analyzers.rules import RULES_BY_ID
from .config import Settings
from .ingest import MANIFEST_FILES, SourceFile, collect_codebase, is_excluded, language_for_filename, manifest_kind
from .models import Finding, SecretInfo
from .taxonomy import owasp_for

log = logging.getLogger(__name__)
SANDBOX_TIMEOUT_SECONDS = 600
SANDBOX_MEMORY_BYTES = 2 * 1024**3
# Réglages transmis à l'analyse isolée : aucun secret n'en fait partie
FORWARDED_SETTINGS = (
    "secuscan_external_engines", "secuscan_opengrep_rules", "max_files", "max_file_bytes", "max_uncompressed_bytes",
)


def new_id() -> str:
    return uuid.uuid4().hex[:12]


def _fingerprint(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


def _normalize(line: str) -> str:
    return re.sub(r"\s+", " ", line).strip()


class SandboxError(RuntimeError):
    pass


@dataclass
class StaticResult:
    files_scanned: int
    lines_scanned: int
    languages: dict[str, int]
    vendored: list[str]
    findings: list[Finding]
    redacted: dict[str, SourceFile]
    dependencies: list[sca.Dependency] = field(default_factory=list)

    def to_json(self) -> str:
        return json.dumps({
            "files_scanned": self.files_scanned, "lines_scanned": self.lines_scanned,
            "languages": self.languages, "vendored": self.vendored,
            "findings": [f.model_dump(mode="json") for f in self.findings],
            "redacted": [asdict(s) for s in self.redacted.values()],
            "dependencies": [asdict(d) for d in self.dependencies],
        }, ensure_ascii=False)

    @classmethod
    def from_json(cls, text: str) -> "StaticResult":
        data = json.loads(text)
        return cls(
            files_scanned=data["files_scanned"], lines_scanned=data["lines_scanned"],
            languages=data["languages"], vendored=data["vendored"],
            findings=[Finding.model_validate(f) for f in data["findings"]],
            redacted={s["path"]: SourceFile(**s) for s in data["redacted"]},
            dependencies=[sca.Dependency(**d) for d in data["dependencies"]],
        )


# ---------------------------------------------------------------------- analyse
def _secrets(scan_id: str, codebase) -> tuple[list[Finding], dict[str, SourceFile]]:
    findings: list[Finding] = []
    redacted_files = {}
    # Les manifests peuvent aussi contenir des jetons (ex. registres privés)
    manifests = [SourceFile(m.path, MANIFEST_FILES[m.name], m.content) for m in codebase.manifests]
    for source in codebase.files + manifests:
        matches = secrets.find_secrets(source)
        clean = secrets.redact(source, matches)
        redacted_files[source.path] = clean
        lines = clean.content.split("\n")
        for m in matches:
            top = max(1, m.line - 3)
            bottom = min(len(lines), m.line + 3)
            findings.append(
                Finding(
                    id=new_id(), scan_id=scan_id, kind="secret", rule_id=m.pattern.id,
                    title=f"Secret exposé : {m.pattern.label}",
                    message="Un secret est écrit en clair dans le code source : toute personne ayant "
                            "accès au dépôt (ou à son historique) peut l'utiliser.",
                    fix_hint="Révoquer le secret, le déplacer dans une variable d'environnement ou un "
                             "coffre-fort de secrets, puis purger l'historique Git.",
                    language=source.language, file=source.path,
                    start_line=m.line, end_line=m.line,
                    snippet="\n".join(lines[top - 1 : bottom]), snippet_start_line=top,
                    cwe="CWE-798", owasp=owasp_for("CWE-798"),
                    raw_severity=m.pattern.severity, severity=m.pattern.severity,
                    fingerprint=_fingerprint(m.pattern.id, source.path, m.fingerprint),
                    secret=SecretInfo(secret_type=m.pattern.label, masked=m.masked, fingerprint=m.fingerprint),
                )
            )
    return findings, redacted_files


def _external_engines(settings: Settings, root: Path, code_files: dict) -> list:
    engines = settings.secuscan_external_engines
    results = []
    if "bandit" in engines:
        results += external.run_bandit(root, [p for p, s in code_files.items() if s.language == "python"])
    if "opengrep" in engines:
        results += external.run_opengrep(root, settings.secuscan_opengrep_rules,
                                         {p: s.language for p, s in code_files.items()})
    return results


def _sast(scan_id: str, settings: Settings, redacted: dict, root: Path, existing: list[Finding]) -> list[Finding]:
    code_files = {p: s for p, s in redacted.items() if not manifest_kind(p.split("/")[-1])}
    raws = [raw for source in code_files.values() for raw in sast.analyze_file(source)]
    # Flux d'un fichier à l'autre : alerte sur l'opération dangereuse, qui cite l'appelant
    for flow in interproc.cross_file_flows(list(code_files.values())):
        rule = RULES_BY_ID[flow.sink.rule_id]
        raws.append(sast.RawFinding(
            kind="sast", rule_id=rule.id, title=rule.title, message=interproc.describe(flow), cwe=rule.cwe,
            severity=rule.severity, file=flow.sink.file, language=code_files[flow.sink.file].language,
            start_line=flow.sink.line, end_line=flow.sink.line,
        ))
    # Moteurs externes (SS-5) : une ligne déjà signalée (règle maison ou secret) n'est pas dupliquée
    flagged = {(f.file, f.start_line) for f in existing} | {(r.file, r.start_line) for r in raws}
    raws += [r for r in _external_engines(settings, root, code_files) if (r.file, r.start_line) not in flagged]

    findings = []
    seen = set()
    for raw in raws:
        # Deux règles qui signalent la même faille (même CWE) sur la même ligne : une seule alerte
        key = (raw.cwe, raw.file, raw.start_line)
        if key in seen:
            continue
        seen.add(key)
        source = code_files[raw.file]
        lines = source.content.split("\n")
        if not 1 <= raw.start_line <= len(lines):
            continue
        excerpt = enclosing_excerpt(lines, source.language, raw.start_line, min(raw.end_line, len(lines)))
        rule = RULES_BY_ID.get(raw.rule_id)
        findings.append(
            Finding(
                id=new_id(), scan_id=scan_id, kind="sast", rule_id=raw.rule_id, title=raw.title,
                message=raw.message, fix_hint=rule.fix_hint if rule else None, language=raw.language,
                file=raw.file, start_line=raw.start_line, end_line=min(raw.end_line, len(lines)),
                snippet=excerpt.code, snippet_start_line=excerpt.start_line,
                cwe=raw.cwe, owasp=owasp_for(raw.cwe),
                raw_severity=raw.severity, severity=raw.severity,
                fingerprint=_fingerprint(raw.rule_id, raw.file, _normalize(lines[raw.start_line - 1])),
            )
        )
    return findings


def _history_secrets(scan_id: str, history_file: Path, current: list[Finding], exclude: list[str]) -> list[Finding]:
    known = {f.secret.fingerprint for f in current if f.secret}
    findings = []
    for h in history.find_history_secrets(history_file.read_text(encoding="utf-8", errors="replace"), known):
        if is_excluded(h.path, exclude):
            continue
        pat = h.match.pattern
        findings.append(Finding(
            id=new_id(), scan_id=scan_id, kind="secret", rule_id=pat.id,
            title=f"Secret dans l'historique Git : {pat.label}",
            message=f"Ce secret a été ajouté par le commit {h.commit} ({h.date}) et ne figure plus dans le code "
                    "actuel, mais il reste lisible par toute personne ayant accès au dépôt et à son historique.",
            fix_hint="Le considérer comme compromis : le révoquer et le remplacer, puis purger l'historique "
                     "(git filter-repo) et demander à chacun de recloner le dépôt.",
            language=language_for_filename(h.path) or "text", file=h.path, start_line=h.line, end_line=h.line,
            snippet=h.redacted_line, snippet_start_line=h.line, cwe="CWE-798", owasp=owasp_for("CWE-798"),
            raw_severity=pat.severity, severity=pat.severity,
            fingerprint=_fingerprint(pat.id, "history", h.match.fingerprint),
            secret=SecretInfo(secret_type=pat.label, masked=h.match.masked, fingerprint=h.match.fingerprint,
                              commit=h.commit, commit_date=h.date),
        ))
    return findings


def analyze_static(root: Path, settings: Settings, scan_id: str, exclude: list[str] | None = None,
                   progress: Callable[[str, float], None] | None = None,
                   history_file: Path | None = None) -> StaticResult:
    progress = progress or (lambda stage, value: None)
    codebase = collect_codebase(root, settings, exclude)
    progress("Détection des secrets", 0.15)
    findings, redacted = _secrets(scan_id, codebase)
    if history_file and history_file.is_file():
        findings += _history_secrets(scan_id, history_file, findings, exclude or [])
    progress("Analyse statique (règles)", 0.3)
    findings += _sast(scan_id, settings, redacted, root, findings)
    return StaticResult(
        files_scanned=len(codebase.files) + len(codebase.manifests), lines_scanned=codebase.line_count,
        languages=codebase.languages, vendored=codebase.vendored, findings=findings, redacted=redacted,
        dependencies=sca.parse_manifests(codebase.manifests),
    )


# ---------------------------------------------------------------------- modes d'isolation
def _request(root: Path, settings: Settings, scan_id: str, exclude: list[str] | None,
             history_file: Path | None = None) -> dict:
    return {"root": str(root.resolve()), "scan_id": scan_id, "exclude": exclude or [],
            "history": str(history_file.resolve()) if history_file else None,
            "settings": {k: getattr(settings, k) for k in FORWARDED_SETTINGS}}


def _settings_from(request: dict) -> Settings:
    # _env_file=None : les fichiers .env (et leurs secrets) ne sont jamais lus côté isolé
    return Settings(_env_file=None, **request["settings"])


def child_env() -> dict[str, str]:
    """Environnement minimal du sous-processus : aucun secret ni réglage de l'application."""
    # Chemins système et dossier utilisateur (caches de Bandit) : aucun secret
    keep = {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "HOME", "USERPROFILE", "LOCALAPPDATA", "APPDATA",
            "LANG", "PYTHONPATH", "PYTHONIOENCODING"}
    env = {k: v for k, v in os.environ.items() if k.upper() in keep}
    env["PYTHONIOENCODING"] = "utf-8"
    return env


def _limit_resources() -> None:  # pragma: no cover — exécuté dans le sous-processus, sous Linux
    import resource
    resource.setrlimit(resource.RLIMIT_AS, (SANDBOX_MEMORY_BYTES, SANDBOX_MEMORY_BYTES))
    resource.setrlimit(resource.RLIMIT_CPU, (SANDBOX_TIMEOUT_SECONDS, SANDBOX_TIMEOUT_SECONDS))


def run_in_process(root: Path, settings: Settings, scan_id: str, exclude: list[str] | None,
                   history_file: Path | None = None) -> StaticResult:
    request = json.dumps(_request(root, settings, scan_id, exclude, history_file))
    try:
        done = subprocess.run(
            [sys.executable, "-m", "secuscan.sandbox", "run"], input=request, capture_output=True, text=True,
            encoding="utf-8", env=child_env(), cwd=Path(__file__).resolve().parent.parent,
            timeout=SANDBOX_TIMEOUT_SECONDS, preexec_fn=_limit_resources if os.name == "posix" else None,
        )
    except subprocess.TimeoutExpired as exc:
        raise SandboxError("Analyse statique interrompue : durée maximale dépassée.") from exc
    if done.returncode != 0:
        raise SandboxError(f"Analyse statique isolée en échec : {done.stderr.strip()[-300:]}")
    return StaticResult.from_json(done.stdout)


def run_in_container(root: Path, settings: Settings, scan_id: str, exclude: list[str] | None,
                     poll: float = 0.5, history_file: Path | None = None) -> StaticResult:
    """Dépose la demande dans le dossier partagé et attend la réponse du conteneur isolé."""
    box = settings.sandbox_dir
    job = new_id()
    tmp = box / f"{job}.request.tmp"
    tmp.write_text(json.dumps(_request(root, settings, scan_id, exclude, history_file)), encoding="utf-8")
    tmp.replace(box / f"{job}.request.json")  # dépôt atomique : jamais lu à moitié écrit
    deadline = time.monotonic() + SANDBOX_TIMEOUT_SECONDS
    result, error = box / f"{job}.result.json", box / f"{job}.error.txt"
    while time.monotonic() < deadline:
        if result.exists():
            try:
                return StaticResult.from_json(result.read_text(encoding="utf-8"))
            finally:
                result.unlink(missing_ok=True)
        if error.exists():
            message = error.read_text(encoding="utf-8")[-300:]
            error.unlink(missing_ok=True)
            raise SandboxError(f"Analyse statique isolée en échec : {message}")
        time.sleep(poll)
    (box / f"{job}.request.json").unlink(missing_ok=True)
    raise SandboxError("Conteneur d'analyse isolée injoignable ou trop lent (service « sandbox » démarré ?).")


def static_analysis(root: Path, settings: Settings, scan_id: str, exclude: list[str] | None = None,
                    progress: Callable[[str, float], None] | None = None,
                    history_file: Path | None = None) -> StaticResult:
    mode = settings.secuscan_sandbox
    if mode == "process":
        return run_in_process(root, settings, scan_id, exclude, history_file)
    if mode == "container":
        return run_in_container(root, settings, scan_id, exclude, history_file=history_file)
    if mode == "ephemeral":
        from .sandbox_docker import run_in_ephemeral_container  # import local : ce module dépend de celui-ci
        return run_in_ephemeral_container(root, settings, scan_id, exclude, history_file)
    return analyze_static(root, settings, scan_id, exclude, progress, history_file)


# ---------------------------------------------------------------------- côté isolé
def _handle(request: dict, allowed_roots: list[Path]) -> StaticResult:
    root = Path(request["root"]).resolve()
    history_file = Path(request["history"]).resolve() if request.get("history") else None
    for path in filter(None, (root, history_file)):
        if allowed_roots and not any(path.is_relative_to(a.resolve()) for a in allowed_roots):
            raise SandboxError(f"Dossier hors du périmètre autorisé : {path}")
    return analyze_static(root, _settings_from(request), str(request["scan_id"]), request.get("exclude"),
                          history_file=history_file)


def serve_once(box: Path, allowed_roots: list[Path]) -> int:
    """Traite les demandes en attente ; renvoie leur nombre."""
    handled = 0
    for req in sorted(box.glob("*.request.json")):
        job = req.name.removesuffix(".request.json")
        running = box / f"{job}.running"
        try:
            req.replace(running)  # un seul conteneur traite une demande
        except OSError:
            continue
        try:
            output = _handle(json.loads(running.read_text(encoding="utf-8")), allowed_roots).to_json()
            tmp = box / f"{job}.result.tmp"
            tmp.write_text(output, encoding="utf-8")
            tmp.replace(box / f"{job}.result.json")
        except Exception as exc:  # noqa: BLE001 — l'erreur est rendue au worker
            (box / f"{job}.error.txt").write_text(f"{type(exc).__name__}: {exc}", encoding="utf-8")
        finally:
            running.unlink(missing_ok=True)
        handled += 1
    return handled


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="secuscan.sandbox")
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="une analyse : demande JSON sur l'entrée standard, résultat sur la sortie")
    run.add_argument("--request", help="demande JSON en argument (conteneur jetable) plutôt que sur l'entrée")
    run.add_argument("--allow", type=Path, action="append", default=[], help="dossier analysable (répétable)")
    serve = sub.add_parser("serve", help="conteneur isolé : traite les demandes déposées dans un dossier")
    serve.add_argument("box", type=Path)
    serve.add_argument("--allow", type=Path, action="append", default=[], help="dossier analysable (répétable)")
    args = parser.parse_args(argv)
    if args.command == "run":
        request = json.loads(args.request if args.request is not None else sys.stdin.read())
        sys.stdout.write(_handle(request, args.allow).to_json())
        return 0
    args.box.mkdir(parents=True, exist_ok=True)
    log.info("Analyse isolée : en attente de demandes dans %s", args.box)
    while True:
        if not serve_once(args.box, args.allow):
            time.sleep(0.5)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    sys.exit(main())
