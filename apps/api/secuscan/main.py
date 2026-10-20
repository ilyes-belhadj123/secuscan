"""API HTTP SecuScan.

Toutes les routes métier exigent une session (SS-2) et sont filtrées par l'organisation courante :
une analyse, une alerte ou un rapport d'une autre organisation répond « introuvable » (404),
sans révéler son existence.
"""
import logging
import re
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, Response

from .accounts import router as accounts_router
from .ai_settings import router as ai_settings_router
from .beta import router as beta_router
from .billing import check_scan_quota
from .billing import router as billing_router
from .branding import report_logo
from .branding import router as branding_router
from .config import DEMO_PROJECT_DIR, Settings, get_settings
from .deps import Context, current_context, get_service, require_admin
from .gitproviders import clone_auth, provider_or_404
from .gitproviders import router as git_router
from .ingest import (
    UploadError,
    Workspace,
    language_for_filename,
    safe_extract_zip,
    validate_git_url,
)
from .models import SEVERITY_ORDER, DismissRequest, Finding, GitRequest, Scan, SnippetRequest
from .pipeline import CloneSpec, ScanService, new_id
from .plans import QuotaExceeded, has_feature
from .reports import build_json, build_pdf, report_json_schema
from .stripe_billing import router as stripe_router
from .training import router as training_router

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")



@asynccontextmanager
async def lifespan(_app: FastAPI):
    """En production, refuse de démarrer avec une configuration dangereuse (HTTP, cookie non sécurisé…)."""
    settings = get_service().settings
    if settings.secuscan_production and (problems := settings.production_problems()):
        raise RuntimeError("Configuration de production incomplète : " + " ; ".join(problems))
    yield


app = FastAPI(title="SecuScan API", version="0.2.0", lifespan=lifespan)
app.include_router(accounts_router)
app.include_router(billing_router)
app.include_router(git_router)
app.include_router(beta_router)
app.include_router(ai_settings_router)
app.include_router(branding_router)
app.include_router(training_router)
app.include_router(stripe_router)

_UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


@app.middleware("http")
async def csrf_origin_check(request: Request, call_next):
    """Protection CSRF : une requête qui modifie des données doit venir d'une origine autorisée.

    Complète le cookie de session SameSite=Lax (non envoyé sur les POST inter-sites).
    """
    if request.method in _UNSAFE_METHODS:
        origin = request.headers.get("origin")
        allowed = get_service().settings.origins
        if (origin and origin not in allowed) or (not origin and request.headers.get("sec-fetch-site") == "cross-site"):
            return JSONResponse({"detail": "Origine de la requête non autorisée"}, status_code=403)
    return await call_next(request)


# Politique de contenu de l'interface : scripts du site uniquement (les styles en ligne viennent de React)
_CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
        "connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Content-Security-Policy", _CSP)
    if get_service().settings.secuscan_cookie_secure:  # servi en HTTPS : le navigateur s'y tient ensuite
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return response


def _scan_or_404(service: ScanService, scan_id: str, ctx: Context) -> Scan:
    scan = service.storage.get_scan(scan_id, org_id=ctx.org_id)
    if not scan:
        raise HTTPException(404, "Analyse introuvable")
    return scan


def _finding_or_404(service: ScanService, finding_id: str, ctx: Context) -> tuple[Finding, Scan]:
    finding = service.storage.get_finding(finding_id)
    scan = service.storage.get_scan(finding.scan_id, org_id=ctx.org_id) if finding else None
    if not (finding and scan):
        raise HTTPException(404, "Alerte introuvable")
    return finding, scan


def _new_scan(service: ScanService, ctx: Context, **fields) -> Scan:
    """Crée une analyse après vérification des quotas de l'offre (402 si la limite est atteinte)."""
    try:
        check_scan_quota(service.storage, ctx.org_id, fields["project_name"])
    except QuotaExceeded as exc:
        raise HTTPException(402, str(exc)) from exc
    org = service.storage.get_org(ctx.org_id)
    return Scan(id=new_id(), org_id=ctx.org_id, created_by=ctx.email, plan=org["plan"] if org else None, **fields)


def _audit(service: ScanService, ctx: Context, action: str, target: str, details: dict) -> None:
    service.storage.audit(action, target, details, org_id=ctx.org_id, actor=ctx.email)


def _safe_filename(name: str) -> str:
    return re.sub(r"[^\w.\-]+", "_", name).strip("._") or "rapport"


def _sort_key(f: Finding):
    return (f.status != "open", SEVERITY_ORDER[f.severity], f.file, f.start_line)


# ---------------------------------------------------------------------- santé (public)
@app.get("/api/health")
def health(settings: Settings = Depends(get_settings)):
    return {
        "status": "ok",
        "ai_enabled": settings.ai_enabled,
        "model": settings.openrouter_model,
        "offline": settings.secuscan_offline,
        "demo_available": DEMO_PROJECT_DIR.is_dir(),
    }


# ---------------------------------------------------------------------- lancement d'analyses
@app.post("/api/scans/demo", status_code=202)
def scan_demo(ctx: Context = Depends(current_context), service: ScanService = Depends(get_service)):
    if not DEMO_PROJECT_DIR.is_dir():
        raise HTTPException(404, "Projet de démonstration absent")
    scan = _new_scan(service, ctx, project_name="Acme Shop (démo)", source="demo")
    service.submit(scan, DEMO_PROJECT_DIR)
    return scan


@app.post("/api/scans/upload", status_code=202)
async def scan_upload(
    file: UploadFile = File(...),
    project_name: str = Form("Projet importé", max_length=120),
    ctx: Context = Depends(current_context),
    service: ScanService = Depends(get_service),
):
    settings = service.settings
    if not (file.filename or "").lower().endswith(".zip"):
        raise HTTPException(400, "Seules les archives .zip sont acceptées.")
    # Quotas vérifiés avant de recevoir l'archive
    scan = _new_scan(service, ctx, project_name=project_name.strip() or "Projet importé", source="upload")
    workspace = Workspace(settings.work_dir)
    try:
        archive = workspace.path / "upload.zip"
        size = 0
        with open(archive, "wb") as out:
            while chunk := await file.read(1024 * 1024):
                size += len(chunk)
                if size > settings.max_upload_bytes:
                    raise UploadError("Archive trop volumineuse (100 Mo maximum).")
                out.write(chunk)
        source_dir = workspace.path / "src"
        source_dir.mkdir()
        safe_extract_zip(archive, source_dir, settings)
        archive.unlink()
    except UploadError as exc:
        workspace.cleanup()
        raise HTTPException(400, str(exc)) from exc
    except Exception:
        workspace.cleanup()
        raise
    service.submit(scan, source_dir, workspace)
    return scan


@app.post("/api/scans/git", status_code=202)
def scan_git(body: GitRequest, ctx: Context = Depends(current_context), service: ScanService = Depends(get_service)):
    branch = (body.branch or "").strip() or None
    auth_header = None
    if body.provider:
        # Dépôt (éventuellement privé) du compte connecté : URL et accès fournis par l'API du fournisseur
        if not body.repo:
            raise HTTPException(400, "Choisissez un dépôt.")
        provider_or_404(service.settings, body.provider)
        url, auth_header, default_branch, repo_name = clone_auth(service, ctx, body.provider, body.repo)
        branch = branch or default_branch or None
    elif body.url:
        url = body.url
        repo_name = url.rstrip("/").removesuffix(".git").split("/")[-1]
    else:
        raise HTTPException(400, "Indiquez l'URL d'un dépôt public ou choisissez un dépôt connecté.")
    try:
        url = validate_git_url(url, branch)
    except UploadError as exc:
        raise HTTPException(400, str(exc)) from exc
    scan = _new_scan(
        service, ctx, project_name=(body.project_name or "").strip() or repo_name, source="git",
        source_url=url + (f"@{branch}" if branch else ""),
    )
    workspace = Workspace(service.settings.work_dir)
    source_dir = workspace.path / "src"
    service.submit(scan, source_dir, workspace, clone=CloneSpec(url, branch, auth_header))
    return scan


@app.post("/api/scans/snippet", status_code=202)
def scan_snippet(body: SnippetRequest, ctx: Context = Depends(current_context), service: ScanService = Depends(get_service)):
    filename = Path(body.filename.replace("\\", "/")).name
    if not language_for_filename(filename):
        raise HTTPException(400, "Extension non supportée (.py, .js, .ts, .php, .java, .cs, .go…).")
    if not body.code.strip():
        raise HTTPException(400, "Le code est vide.")
    scan = _new_scan(service, ctx, project_name=body.project_name.strip() or "Extrait de code", source="snippet")
    workspace = Workspace(service.settings.work_dir)
    (workspace.path / filename).write_text(body.code, encoding="utf-8")
    service.submit(scan, workspace.path, workspace)
    return scan


# ---------------------------------------------------------------------- consultation
@app.get("/api/scans")
def list_scans(ctx: Context = Depends(current_context), service: ScanService = Depends(get_service)):
    return service.storage.list_scans(org_id=ctx.org_id)


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: str, ctx: Context = Depends(current_context), service: ScanService = Depends(get_service)):
    return _scan_or_404(service, scan_id, ctx)


@app.get("/api/scans/{scan_id}/history")
def scan_history(scan_id: str, ctx: Context = Depends(current_context), service: ScanService = Depends(get_service)):
    """Évolution du score pour le projet de cette analyse."""
    scan = _scan_or_404(service, scan_id, ctx)
    scans = [
        s for s in service.storage.list_scans(org_id=ctx.org_id)
        if s.project_name == scan.project_name and s.status == "completed"
    ]
    return [
        {"id": s.id, "created_at": s.created_at, "score": s.score, "total": s.summary.total,
         "by_severity": s.summary.by_severity}
        for s in reversed(scans)
    ]


@app.get("/api/scans/{scan_id}/findings")
def list_findings(scan_id: str, ctx: Context = Depends(current_context), service: ScanService = Depends(get_service)):
    _scan_or_404(service, scan_id, ctx)
    return sorted(service.storage.list_findings(scan_id), key=_sort_key)


@app.get("/api/findings/{finding_id}")
def get_finding(finding_id: str, ctx: Context = Depends(current_context), service: ScanService = Depends(get_service)):
    return _finding_or_404(service, finding_id, ctx)[0]


@app.post("/api/findings/{finding_id}/dismiss")
def dismiss_finding(finding_id: str, body: DismissRequest, ctx: Context = Depends(current_context),
                    service: ScanService = Depends(get_service)):
    finding, scan = _finding_or_404(service, finding_id, ctx)
    finding.status = "dismissed"
    finding.dismiss_reason, finding.dismiss_justification = body.reason, body.justification.strip()
    service.storage.save_findings([finding])
    service.storage.save_dismissal(
        scan.project_name, finding.fingerprint, body.reason, finding.dismiss_justification, org_id=ctx.org_id
    )
    service.refresh_scan(scan)
    _audit(service, ctx, "finding.dismissed", finding.id, {
        "project": scan.project_name, "title": finding.title, "location": f"{finding.file}:{finding.start_line}",
        "reason": body.reason, "justification": finding.dismiss_justification,
    })
    return finding


@app.get("/api/costs")
def ai_costs(ctx: Context = Depends(current_context), service: ScanService = Depends(get_service)):
    """Coût IA par analyse de l'organisation (SS-12) : appels, cache, jetons et estimation en dollars."""
    settings = service.settings
    plan = service.storage.get_org(ctx.org_id)["plan"]
    max_calls, max_tokens = settings.ai_budget_for(plan)
    scans = [s for s in service.storage.list_scans(org_id=ctx.org_id) if s.status == "completed"]
    rows = [
        {"id": s.id, "project_name": s.project_name, "created_at": s.created_at, "plan": s.summary.plan,
         "calls": s.summary.ai_calls, "cache_hits": s.summary.ai_cache_hits, "tokens": s.summary.ai_tokens,
         "cost_usd": s.summary.ai_cost_usd, "budget_refused": s.summary.ai_budget_refused,
         "lines": s.summary.lines_scanned}
        for s in scans
    ]
    return {
        "plan": plan, "budget_calls": max_calls, "budget_tokens": max_tokens,
        "price_input_per_mtok": settings.secuscan_ai_price_input_per_mtok,
        "price_output_per_mtok": settings.secuscan_ai_price_output_per_mtok,
        "total_cost_usd": round(sum(r["cost_usd"] for r in rows), 4),
        "total_tokens": sum(r["tokens"] for r in rows),
        "scans": rows,
    }


@app.get("/api/audit")
def audit_log(ctx: Context = Depends(require_admin), service: ScanService = Depends(get_service)):
    """Journal d'audit de l'organisation, réservé aux administrateurs (SS-19)."""
    return service.storage.list_audit(ctx.org_id)


# ---------------------------------------------------------------------- rapports
@app.get("/api/scans/{scan_id}/report.pdf")
def report_pdf(
    scan_id: str,
    prepared_for: str | None = Query(None, max_length=120),
    prepared_by: str | None = Query(None, max_length=120),
    ctx: Context = Depends(current_context),
    service: ScanService = Depends(get_service),
):
    scan = _scan_or_404(service, scan_id, ctx)
    if scan.status != "completed":
        raise HTTPException(409, "L'analyse n'est pas terminée")
    prepared_for = (prepared_for or "").strip() or None
    prepared_by = (prepared_by or "").strip() or None
    org = service.storage.get_org(ctx.org_id)
    if prepared_by and not has_feature(org["plan"], "white_label"):
        raise HTTPException(402, "La marque blanche (« Réalisé par ») est incluse dans l'offre Business.")
    logo = report_logo(service, ctx.org_id)
    pdf = build_pdf(scan, service.storage.list_findings(scan_id), prepared_for, prepared_by, logo)
    _audit(service, ctx, "report.exported", scan_id,
           {"format": "pdf", "project": scan.project_name, "prepared_for": prepared_for, "prepared_by": prepared_by,
            "logo": logo is not None})
    name = _safe_filename(f"secuscan-{scan.project_name}-{scan.id}") + ".pdf"
    return Response(pdf, media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="{name}"'})


@app.get("/api/scans/{scan_id}/report.json")
def report_json(scan_id: str, ctx: Context = Depends(current_context), service: ScanService = Depends(get_service)):
    scan = _scan_or_404(service, scan_id, ctx)
    if scan.status != "completed":
        raise HTTPException(409, "L'analyse n'est pas terminée")
    _audit(service, ctx, "report.exported", scan_id, {"format": "json", "project": scan.project_name})
    name = _safe_filename(f"secuscan-{scan.project_name}-{scan.id}") + ".json"
    return JSONResponse(
        build_json(scan, service.storage.list_findings(scan_id)),
        headers={"Content-Disposition": f'attachment; filename="{name}"'},
    )


@app.get("/api/schemas/report-v1.json")
def report_schema():
    return report_json_schema()


# ---------------------------------------------------------------------- interface compilée (mise en ligne)
# Déclarée en dernier : toute route /api/... déjà définie est prioritaire.
@app.get("/{path:path}", include_in_schema=False)
def web_app(path: str, service: ScanService = Depends(get_service)):
    """Fichiers de l'interface (apps/web/dist) ; toute autre adresse renvoie index.html (routage React)."""
    if path == "api" or path.startswith("api/"):
        raise HTTPException(404, "Ressource introuvable")
    dist = service.settings.secuscan_web_dist.resolve()
    index = dist / "index.html"
    if not index.is_file():
        raise HTTPException(404, "Interface non compilée (npm run build)")
    target = (dist / path).resolve()
    if path and target.is_file() and target.is_relative_to(dist):
        # Fichiers de assets/ nommés d'après leur contenu : mis en cache sans limite
        cache = "public, max-age=31536000, immutable" if path.startswith("assets/") else "no-cache"
        return FileResponse(target, headers={"Cache-Control": cache})
    return FileResponse(index, headers={"Cache-Control": "no-cache"})
