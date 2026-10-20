"""SS-18 — logo de l'organisation dans le rapport PDF (marque blanche, offre Business).

L'image envoyée n'est jamais conservée telle quelle : elle est décodée (PNG ou JPEG uniquement,
dimensions bornées avant décodage contre les bombes de décompression), réduite, puis réencodée
en PNG. Les métadonnées et tout contenu caché dans le fichier d'origine sont donc écartés.
"""
import io

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from fastapi.responses import Response
from PIL import Image, UnidentifiedImageError

from .deps import Context, current_context, get_service, require_admin
from .pipeline import ScanService
from .plans import has_feature

router = APIRouter(prefix="/api/org")

MAX_LOGO_BYTES = 1024 * 1024
MAX_SOURCE_PIXELS = 4000 * 4000
LOGO_BOX = (600, 200)  # taille maximale conservée (le PDF l'affiche sur 14 mm de haut)


class LogoError(ValueError):
    pass


def normalize_logo(data: bytes) -> bytes:
    """Image PNG ou JPEG → PNG réduit et réencodé ; LogoError si le fichier n'est pas acceptable."""
    if len(data) > MAX_LOGO_BYTES:
        raise LogoError("Logo trop lourd (1 Mo maximum).")
    try:
        with Image.open(io.BytesIO(data)) as img:
            if img.format not in ("PNG", "JPEG"):
                raise LogoError("Format non pris en charge : PNG ou JPEG uniquement.")
            width, height = img.size
            if width * height > MAX_SOURCE_PIXELS:
                raise LogoError("Image trop grande (4 000 × 4 000 pixels maximum).")
            img.load()
            logo = img.convert("RGBA")
    except (UnidentifiedImageError, OSError, Image.DecompressionBombError) as exc:
        raise LogoError("Fichier image illisible.") from exc
    logo.thumbnail(LOGO_BOX)
    out = io.BytesIO()
    logo.save(out, format="PNG", optimize=True)
    return out.getvalue()


def report_logo(service: ScanService, org_id: str) -> bytes | None:
    """Logo à placer dans le rapport : seulement si l'offre inclut la marque blanche."""
    org = service.storage.get_org(org_id)
    if not org or not has_feature(org["plan"], "white_label"):
        return None
    return service.storage.get_org_logo(org_id)


@router.get("/logo")
def get_logo(ctx: Context = Depends(current_context), service: ScanService = Depends(get_service)):
    png = service.storage.get_org_logo(ctx.org_id)
    if png is None:
        raise HTTPException(404, "Aucun logo")
    return Response(png, media_type="image/png", headers={"Cache-Control": "no-store"})


@router.put("/logo")
async def upload_logo(file: UploadFile = File(...), ctx: Context = Depends(require_admin),
                      service: ScanService = Depends(get_service)):
    org = service.storage.get_org(ctx.org_id)
    if not has_feature(org["plan"], "white_label"):
        raise HTTPException(402, "Le logo dans les rapports est inclus dans l'offre Business.")
    data = await file.read(MAX_LOGO_BYTES + 1)
    try:
        png = normalize_logo(data)
    except LogoError as exc:
        raise HTTPException(400, str(exc)) from exc
    service.storage.set_org_logo(ctx.org_id, png)
    service.storage.audit("org.logo_updated", ctx.org_id, {"bytes": len(png)}, org_id=ctx.org_id, actor=ctx.email)
    return {"ok": True}


@router.delete("/logo")
def delete_logo(ctx: Context = Depends(require_admin), service: ScanService = Depends(get_service)):
    if service.storage.delete_org_logo(ctx.org_id):
        service.storage.audit("org.logo_deleted", ctx.org_id, {}, org_id=ctx.org_id, actor=ctx.email)
    return {"ok": True}
