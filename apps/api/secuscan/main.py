"""API HTTP SecuScan (démo)."""
import logging
import re
from pathlib import Path

from fastapi import Depends, FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import JSONResponse, Response

from .config import DEMO_PROJECT_DIR, Settings, get_settings
from .ingest import UploadError, Workspace, language_for_filename, safe_extract_zip
from .models import SEVERITY_ORDER, DismissRequest, Finding, Scan, SnippetRequest
from .pipeline import ScanService, new_id
from .reports import build_json, build_pdf, report_json_schema
from .storage import Storage

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

app = FastAPI(title="SecuScan API", version="0.1.0")

_service: ScanService | None = None


def get_service() -> ScanService:
    global _service
    if _service is None:
        settings = get_settings()
        _service = ScanService(settings, Storage(settings.data_dir / "secuscan.db"))
    return _service


def _scan_or_404(service: ScanService, scan_id: str) -> Scan:
    scan = service.storage.get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Analyse introuvable")
    return scan


def _safe_filename(name: str) -> str:
    return re.sub(r"[^\w.\-]+", "_", name).strip("._") or "rapport"


def _sort_key(f: Finding):
    return (f.status != "open", SEVERITY_ORDER[f.severity], f.file, f.start_line)


# ---------------------------------------------------------------------- santé
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
def scan_demo(service: ScanService = Depends(get_service)):
    if not DEMO_PROJECT_DIR.is_dir():
        raise HTTPException(404, "Projet de démonstration absent")
    scan = Scan(id=new_id(), project_name="Acme Shop (démo)", source="demo")
    service.submit(scan, DEMO_PROJECT_DIR)
    return scan


@app.post("/api/scans/upload", status_code=202)
async def scan_upload(
    file: UploadFile = File(...),
    project_name: str = Form("Projet importé", max_length=120),
    service: ScanService = Depends(get_service),
):
    settings = service.settings
    if not (file.filename or "").lower().endswith(".zip"):
        raise HTTPException(400, "Seules les archives .zip sont acceptées.")
    workspace = Workspace(settings.data_dir / "work")
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
    scan = Scan(id=new_id(), project_name=project_name.strip() or "Projet importé", source="upload")
    service.submit(scan, source_dir, workspace)
    return scan


@app.post("/api/scans/snippet", status_code=202)
def scan_snippet(body: SnippetRequest, service: ScanService = Depends(get_service)):
    filename = Path(body.filename.replace("\\", "/")).name
    if not language_for_filename(filename):
        raise HTTPException(400, "Extension non supportée (.py, .js, .ts, .php, .java…).")
    if not body.code.strip():
        raise HTTPException(400, "Le code est vide.")
    workspace = Workspace(service.settings.data_dir / "work")
    (workspace.path / filename).write_text(body.code, encoding="utf-8")
    scan = Scan(id=new_id(), project_name=body.project_name.strip() or "Extrait de code", source="snippet")
    service.submit(scan, workspace.path, workspace)
    return scan


# ---------------------------------------------------------------------- consultation
@app.get("/api/scans")
def list_scans(service: ScanService = Depends(get_service)):
    return service.storage.list_scans()


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: str, service: ScanService = Depends(get_service)):
    return _scan_or_404(service, scan_id)


@app.get("/api/scans/{scan_id}/history")
def scan_history(scan_id: str, service: ScanService = Depends(get_service)):
    """Évolution du score pour le projet de cette analyse."""
    scan = _scan_or_404(service, scan_id)
    scans = [s for s in service.storage.list_scans() if s.project_name == scan.project_name and s.status == "completed"]
    return [
        {"id": s.id, "created_at": s.created_at, "score": s.score, "total": s.summary.total,
         "by_severity": s.summary.by_severity}
        for s in reversed(scans)
    ]


@app.get("/api/scans/{scan_id}/findings")
def list_findings(scan_id: str, service: ScanService = Depends(get_service)):
    _scan_or_404(service, scan_id)
    return sorted(service.storage.list_findings(scan_id), key=_sort_key)


@app.get("/api/findings/{finding_id}")
def get_finding(finding_id: str, service: ScanService = Depends(get_service)):
    finding = service.storage.get_finding(finding_id)
    if not finding:
        raise HTTPException(404, "Alerte introuvable")
    return finding


@app.post("/api/findings/{finding_id}/dismiss")
def dismiss_finding(finding_id: str, body: DismissRequest, service: ScanService = Depends(get_service)):
    finding = service.storage.get_finding(finding_id)
    if not finding:
        raise HTTPException(404, "Alerte introuvable")
    scan = _scan_or_404(service, finding.scan_id)
    finding.status = "dismissed"
    finding.dismiss_reason, finding.dismiss_justification = body.reason, body.justification.strip()
    service.storage.save_findings([finding])
    service.storage.save_dismissal(scan.project_name, finding.fingerprint, body.reason, finding.dismiss_justification)
    service.storage.audit("finding.dismissed", finding.id, {"reason": body.reason, "rule": finding.rule_id})
    return finding


@app.get("/api/audit")
def audit_log(service: ScanService = Depends(get_service)):
    return service.storage.list_audit()


# ---------------------------------------------------------------------- rapports
@app.get("/api/scans/{scan_id}/report.pdf")
def report_pdf(scan_id: str, service: ScanService = Depends(get_service)):
    scan = _scan_or_404(service, scan_id)
    if scan.status != "completed":
        raise HTTPException(409, "L'analyse n'est pas terminée")
    pdf = build_pdf(scan, service.storage.list_findings(scan_id))
    service.storage.audit("report.exported", scan_id, {"format": "pdf"})
    name = _safe_filename(f"secuscan-{scan.project_name}-{scan.id}") + ".pdf"
    return Response(pdf, media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="{name}"'})


@app.get("/api/scans/{scan_id}/report.json")
def report_json(scan_id: str, service: ScanService = Depends(get_service)):
    scan = _scan_or_404(service, scan_id)
    if scan.status != "completed":
        raise HTTPException(409, "L'analyse n'est pas terminée")
    service.storage.audit("report.exported", scan_id, {"format": "json"})
    name = _safe_filename(f"secuscan-{scan.project_name}-{scan.id}") + ".json"
    return JSONResponse(
        build_json(scan, service.storage.list_findings(scan_id)),
        headers={"Content-Disposition": f'attachment; filename="{name}"'},
    )


@app.get("/api/schemas/report-v1.json")
def report_schema():
    return report_json_schema()
