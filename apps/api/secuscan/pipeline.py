"""Pipeline d'analyse : collecte → secrets → règles → dépendances → IA → scoring → stockage."""
import hashlib
import logging
import re
import time
import uuid
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from .ai.enricher import AIBudget, AIUnavailable, BudgetExceeded, Enricher
from .analyzers import sast, sca, secrets
from .analyzers.context import enclosing_excerpt, file_header
from .analyzers.rules import RULES_BY_ID
from .config import Settings
from .ingest import MANIFEST_FILES, CodeBase, SourceFile, Workspace, collect_codebase
from .models import SEVERITY_ORDER, DependencyInfo, Finding, Scan, SecretInfo, Severity, now_iso
from .scoring import apply_severity, project_score
from .storage import Storage
from .taxonomy import CWE_DEPENDENCY, owasp_for

log = logging.getLogger(__name__)


# Points d'entrée (routes HTTP, lecture des entrées) : les fichiers qui en ont sont relus en priorité
_ENTRY_POINT = re.compile(
    r"@app\.route|@\w+\.(get|post|put|delete|route)\(|\bapp\.(get|post|put|delete|use)\(|router\.\w+\(|"
    r"request\.(args|form|json|get_data)|req\.(query|params|body)|\$_(GET|POST|REQUEST|COOKIE)|"
    r"getParameter\(|@(Get|Post|Request)Mapping"
)

_KIND_PRIORITY = {"sast": 0, "ai": 0, "secret": 0, "dependency": 1}


def new_id() -> str:
    return uuid.uuid4().hex[:12]


def _fingerprint(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


def _normalize(line: str) -> str:
    return re.sub(r"\s+", " ", line).strip()


class ScanService:
    def __init__(self, settings: Settings, storage: Storage):
        self.settings = settings
        self.storage = storage
        self.executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="scan")

    # ------------------------------------------------------------------ API publique
    def submit(
        self, scan: Scan, root: Path, workspace: Workspace | None = None,
        prepare: tuple[str, Callable[[], None]] | None = None,
    ) -> None:
        """Lance l'analyse en tâche de fond. `prepare` = (libellé, étape préalable), ex. clonage Git."""
        self.storage.save_scan(scan)
        self._audit(scan, "scan.created", {"project": scan.project_name, "source": scan.source})
        self.executor.submit(self._run_safely, scan, root, workspace, prepare)

    def _audit(self, scan: Scan, action: str, details: dict) -> None:
        self.storage.audit(action, scan.id, details, org_id=scan.org_id or "", actor=scan.created_by or "")

    def _run_safely(self, scan: Scan, root: Path, workspace: Workspace | None, prepare=None) -> None:
        try:
            if prepare:
                label, step = prepare
                scan.status = "running"
                self._progress(scan, label, 0.02)
                step()
            self.run(scan, root)
        except Exception as exc:  # noqa: BLE001 — l'erreur est remontée à l'utilisateur
            log.exception("Analyse %s échouée", scan.id)
            scan.status, scan.error, scan.stage = "failed", str(exc), "Échec"
            self.storage.save_scan(scan)
            self._audit(scan, "scan.failed", {"project": scan.project_name, "error": str(exc)[:300]})
        finally:
            if workspace:
                workspace.cleanup()  # le code importé est supprimé après analyse

    # ------------------------------------------------------------------ étapes
    def _progress(self, scan: Scan, stage: str, progress: float) -> None:
        scan.stage, scan.progress = stage, round(progress, 3)
        self.storage.save_scan(scan)

    def run(self, scan: Scan, root: Path) -> list[Finding]:
        started = time.monotonic()
        scan.status = "running"
        scan.ai_enabled = self.settings.ai_enabled
        self._progress(scan, "Lecture du code et détection des langages", 0.05)
        codebase = collect_codebase(root, self.settings)
        scan.summary.files_scanned = len(codebase.files) + len(codebase.manifests)
        scan.summary.lines_scanned = codebase.line_count
        scan.summary.languages = codebase.languages

        self._progress(scan, "Détection des secrets", 0.15)
        findings, redacted = self._secrets(scan, codebase)

        self._progress(scan, "Analyse statique (règles)", 0.3)
        findings += self._sast(scan, redacted)

        self._progress(scan, "Analyse des dépendances", 0.35)
        findings += self._dependencies(scan, codebase, redacted)

        enricher = Enricher(self.settings, self.storage, AIBudget(*self.settings.ai_budget_for(self._plan(scan))))
        findings += self._logic(scan, findings, redacted, enricher)

        findings = self._apply_dismissals(scan, findings)
        self._enrich(scan, findings, redacted, enricher)
        self._record_ai_usage(scan, enricher)

        self._progress(scan, "Calcul du score", 0.97)
        for f in findings:
            apply_severity(f)
        self._compare_with_previous(scan, findings)
        self._summarize(scan, findings)
        scan.score = project_score(findings)
        scan.summary.duration_seconds = round(time.monotonic() - started, 1)
        self.storage.save_findings(findings)
        scan.status, scan.stage, scan.progress, scan.completed_at = "completed", "Terminée", 1.0, now_iso()
        self.storage.save_scan(scan)
        self._audit(scan, "scan.completed",
                    {"project": scan.project_name, "findings": scan.summary.total, "score": scan.score})
        return findings

    def _secrets(self, scan: Scan, codebase: CodeBase):
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
                        id=new_id(), scan_id=scan.id, kind="secret", rule_id=m.pattern.id,
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

    def _sast(self, scan: Scan, redacted: dict) -> list[Finding]:
        findings = []
        seen = set()
        for source in redacted.values():
            if source.path.split("/")[-1] in MANIFEST_FILES:
                continue
            lines = source.content.split("\n")
            for raw in sast.analyze_file(source):
                # Deux règles qui signalent la même faille (même CWE) sur la même ligne : une seule alerte
                key = (raw.cwe, raw.file, raw.start_line)
                if key in seen:
                    continue
                seen.add(key)
                excerpt = enclosing_excerpt(lines, source.language, raw.start_line, raw.end_line)
                rule = RULES_BY_ID[raw.rule_id]
                findings.append(
                    Finding(
                        id=new_id(), scan_id=scan.id, kind="sast", rule_id=raw.rule_id, title=raw.title,
                        message=raw.message, fix_hint=rule.fix_hint, language=raw.language, file=raw.file,
                        start_line=raw.start_line, end_line=raw.end_line,
                        snippet=excerpt.code, snippet_start_line=excerpt.start_line,
                        cwe=raw.cwe, owasp=owasp_for(raw.cwe),
                        raw_severity=raw.severity, severity=raw.severity,
                        fingerprint=_fingerprint(raw.rule_id, raw.file, _normalize(lines[raw.start_line - 1])),
                    )
                )
        return findings

    def _dependencies(self, scan: Scan, codebase: CodeBase, redacted: dict) -> list[Finding]:
        deps = sca.parse_manifests(codebase.manifests)
        if not deps:
            return []
        client = sca.OSVClient(self.storage, offline=self.settings.secuscan_offline)
        findings = []
        vulnerable = sca.scan_dependencies(deps, client)
        scan.summary.warnings += client.errors
        for vuln in vulnerable:
            dep = vuln.dependency
            lines = redacted[dep.manifest].content.split("\n")
            if dep.ecosystem == "Maven":  # groupId / artifactId / version sur des lignes voisines
                top, bottom = max(1, dep.line - 1), min(len(lines), dep.line + 1)
            else:
                top = bottom = dep.line
            main = vuln.advisories[0]
            cve = main.aliases[0] if main.aliases else main.id
            count = len(vuln.advisories)
            findings.append(
                Finding(
                    id=new_id(), scan_id=scan.id, kind="dependency", rule_id=f"SCA-{dep.ecosystem.upper()}",
                    title=f"Dépendance vulnérable : {dep.name} {dep.version}",
                    message=f"{count} vulnérabilité{'s' if count > 1 else ''} connue{'s' if count > 1 else ''} "
                            f"(dont {cve}) : {main.summary}",
                    fix_hint=(f"Mettre à jour vers {vuln.fixed_version} ou une version ultérieure."
                              if vuln.fixed_version else "Aucune version corrigée : remplacer la bibliothèque."),
                    language=MANIFEST_FILES[dep.manifest.split("/")[-1]], file=dep.manifest,
                    start_line=dep.line, end_line=dep.line,
                    snippet="\n".join(lines[top - 1 : bottom]), snippet_start_line=top,
                    cwe=CWE_DEPENDENCY, owasp=owasp_for(CWE_DEPENDENCY),
                    raw_severity=vuln.severity, severity=vuln.severity,
                    fingerprint=_fingerprint("SCA", dep.ecosystem, dep.name.lower(), dep.version),
                    dependency=DependencyInfo(
                        ecosystem=dep.ecosystem, package=dep.name, version=dep.version, manifest=dep.manifest,
                        advisories=vuln.advisories, fixed_version=vuln.fixed_version,
                    ),
                )
            )
        return findings

    def _apply_dismissals(self, scan: Scan, findings: list[Finding]) -> list[Finding]:
        dismissed = self.storage.dismissals_for(scan.project_name, org_id=scan.org_id or "")
        for f in findings:
            if f.fingerprint in dismissed:
                f.status = "dismissed"
                f.dismiss_reason, f.dismiss_justification = dismissed[f.fingerprint]
        return findings

    def _logic(self, scan: Scan, findings: list[Finding], redacted: dict, enricher: Enricher) -> list[Finding]:
        """Revue IA de chaque fichier de code pour les failles logiques non couvertes par les règles."""
        candidates = [
            src for path, src in redacted.items()
            if path.split("/")[-1] not in MANIFEST_FILES
            and src.content.count("\n") < self.settings.secuscan_logic_max_lines
        ]
        # Budget : au plus une part des appels, en commençant par les fichiers exposés (routes, entrées)
        limit = min(
            self.settings.secuscan_logic_max_files,
            int(enricher.budget.max_calls * self.settings.secuscan_logic_budget_share),
        )
        candidates.sort(key=lambda s: (-len(_ENTRY_POINT.findall(s.content)), s.path))
        sources = candidates[:limit]
        if skipped := len(candidates) - len(sources):
            scan.summary.warnings.append(
                f"Revue logique IA limitée aux {len(sources)} fichiers les plus exposés ({skipped} non relus)."
            )
        if not sources:
            return []
        flagged: dict[str, list[int]] = {}
        for f in findings:
            flagged.setdefault(f.file, []).append(f.start_line)

        self._progress(scan, f"Revue logique par l'IA (0/{len(sources)})", 0.4)
        results: list[Finding] = []
        with ThreadPoolExecutor(max_workers=max(1, self.settings.secuscan_ai_concurrency)) as pool:
            futures = {pool.submit(enricher.discover_logic_flaws, src, flagged.get(src.path, [])): src for src in sources}
            for done, future in enumerate(as_completed(futures), start=1):
                src = futures[future]
                try:
                    flaws = future.result()
                except AIUnavailable:
                    flaws = []  # sans IA ni cache, cette couche est simplement absente
                except Exception:  # noqa: BLE001
                    log.exception("Revue logique de %s échouée", src.path)
                    flaws = []
                lines = src.content.split("\n")
                for flaw in flaws:
                    # Une faille déjà couverte par une règle sur les mêmes lignes n'est pas dupliquée
                    if any(flaw.start_line <= line <= flaw.end_line for line in flagged.get(src.path, [])):
                        continue
                    excerpt = enclosing_excerpt(lines, src.language, flaw.start_line, flaw.end_line)
                    results.append(
                        Finding(
                            id=new_id(), scan_id=scan.id, kind="ai", rule_id="AI-LOGIC", title=flaw.title,
                            message=flaw.message or "Faille logique détectée par la revue IA du fichier.",
                            fix_hint="Voir le correctif proposé par l'IA.",
                            language=src.language, file=src.path,
                            start_line=flaw.start_line, end_line=flaw.end_line,
                            snippet=excerpt.code, snippet_start_line=excerpt.start_line,
                            cwe=flaw.cwe, owasp=owasp_for(flaw.cwe),
                            raw_severity=flaw.severity, severity=flaw.severity,
                            fingerprint=_fingerprint("AI", src.path, flaw.cwe or "", _normalize(lines[flaw.start_line - 1])),
                        )
                    )
                self._progress(scan, f"Revue logique par l'IA ({done}/{len(sources)})", 0.4 + 0.1 * done / len(sources))
        return results

    def _enrich(self, scan: Scan, findings: list[Finding], redacted: dict, enricher: Enricher) -> None:
        # Priorité : le code avant les dépendances, du plus grave au moins grave (le budget s'épuise par la fin)
        todo = sorted(
            (f for f in findings if f.status == "open"),
            key=lambda f: (_KIND_PRIORITY[f.kind], SEVERITY_ORDER[f.severity]),
        )
        # Dépendances : l'IA n'explique que les plus graves, les autres reçoivent une explication OSV locale
        severe_deps = [
            f for f in todo if f.kind == "dependency" and f.severity in (Severity.critical, Severity.high)
        ]
        deps_for_ai = (
            {f.id for f in severe_deps[: self.settings.secuscan_ai_max_dependency_reviews]}
            if self.settings.ai_enabled else set()
        )
        for f in todo:
            if f.kind == "dependency" and f.id not in deps_for_ai:
                f.ai = Enricher.local_dependency_review(f)
        todo = [f for f in todo if f.ai is None]

        headers = {path: file_header(src.content.split("\n")) for path, src in redacted.items()}
        self._progress(scan, f"Enrichissement IA (0/{len(todo)})", 0.5)

        def work(f: Finding):
            if f.kind == "dependency":
                return enricher.review_dependency(f)
            source = redacted.get(f.file)
            return enricher.review_code_finding(f, headers.get(f.file, ""), source.content if source else None)

        errors = refused = 0
        with ThreadPoolExecutor(max_workers=max(1, self.settings.secuscan_ai_concurrency)) as pool:
            futures = {pool.submit(work, f): f for f in todo}
            for done, future in enumerate(as_completed(futures), start=1):
                f = futures[future]
                try:
                    f.ai = future.result()
                except BudgetExceeded as exc:
                    f.ai_error = str(exc)
                    refused += 1
                except AIUnavailable as exc:
                    f.ai_error = str(exc)
                    errors += 1
                except Exception as exc:  # noqa: BLE001 — une alerte ne doit pas faire échouer le scan
                    log.exception("Enrichissement IA de %s échoué", f.id)
                    f.ai_error = f"Erreur IA : {exc}"
                    errors += 1
                self._progress(scan, f"Enrichissement IA ({done}/{len(todo)})", 0.5 + 0.45 * done / len(todo))

        s = scan.summary
        s.ai_errors = errors + refused
        s.ai_budget_refused = refused
        if not self.settings.ai_enabled and errors:
            s.warnings.append(
                "IA non configurée : ni validation des faux positifs, ni revue logique ; "
                "les explications et correctifs affichés sont ceux, génériques, des règles."
            )
        elif errors:
            s.warnings.append(f"{errors} alerte(s) sans analyse IA (service IA indisponible).")
        if refused:
            max_calls, max_tokens = self.settings.ai_budget_for(self._plan(scan))
            s.warnings.append(
                f"Budget IA atteint (offre {self._plan(scan)} : {max_calls} appels / "
                f"{max_tokens // 1000} k jetons par analyse) : {refused} alerte(s) parmi les moins graves "
                f"affichées avec l'explication générique de leur règle."
            )

    def _record_ai_usage(self, scan: Scan, enricher: Enricher) -> None:
        s = scan.summary
        s.ai_calls = enricher.stats.calls
        s.ai_cache_hits = enricher.stats.cache_hits
        s.ai_tokens = enricher.stats.tokens
        s.ai_cost_usd = round(enricher.stats.cost_usd(self.settings), 4)
        s.ai_budget_calls = enricher.budget.max_calls
        s.plan = self._plan(scan)

    def _plan(self, scan: Scan) -> str:
        return scan.plan or self.settings.secuscan_plan

    def _compare_with_previous(self, scan: Scan, findings: list[Finding]) -> None:
        previous = self.storage.previous_completed_scan(scan.project_name, scan.created_at, org_id=scan.org_id or "")
        if not previous:
            return
        before = {f.fingerprint for f in self.storage.list_findings(previous.id) if f.status == "open"}
        now = {f.fingerprint for f in findings if f.status == "open"}
        scan.previous_scan_id = previous.id
        scan.new_findings = len(now - before)
        scan.fixed_findings = len(before - now)

    def refresh_scan(self, scan: Scan) -> None:
        """Recalcule synthèse et score après une action utilisateur (ex. alerte ignorée)."""
        findings = self.storage.list_findings(scan.id)
        self._summarize(scan, findings)
        scan.score = project_score(findings)
        self.storage.save_scan(scan)

    def _summarize(self, scan: Scan, findings: list[Finding]) -> None:
        s = scan.summary
        visible = [f for f in findings if f.status == "open"]
        s.total = len(visible)
        s.by_severity = {sev.value: sum(1 for f in visible if f.severity == sev) for sev in Severity}
        s.by_kind = {k: sum(1 for f in visible if f.kind == k) for k in ("sast", "ai", "secret", "dependency")}
        by_owasp: dict[str, int] = {}
        for f in visible:
            if f.owasp:
                by_owasp[f.owasp] = by_owasp.get(f.owasp, 0) + 1
        s.by_owasp = dict(sorted(by_owasp.items(), key=lambda kv: -kv[1]))
        s.false_positives = sum(1 for f in findings if f.status == "false_positive")
        s.dismissed = sum(1 for f in findings if f.status == "dismissed")
