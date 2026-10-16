"""Paramètres IA modifiables depuis l'interface : clé OpenRouter et modèle.

- La clé n'est jamais renvoyée au navigateur : seuls ses 4 derniers caractères sont affichés.
- Clé et modèle sont testés auprès d'OpenRouter avant d'être enregistrés.
- Enregistrement dans le fichier .env (exclu de Git) et application immédiate, sans redémarrage.
- Réservé aux administrateurs de l'installation : la clé sert à toutes les organisations.
- Le modèle se choisit dans le catalogue OpenRouter ; son tarif est repris pour l'estimation des coûts.
"""
import logging
import os
import re
import threading
import time
from pathlib import Path

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from .ai import enricher
from .config import Settings
from .deps import Context, get_service, require_installation_admin
from .pipeline import ScanService

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/settings")
CATALOG_TTL_SECONDS = 3600
_catalog: dict = {"models": [], "fetched_at": 0.0}
_catalog_lock = threading.Lock()

# Formats stricts : une valeur ne peut pas contenir de retour à la ligne ni injecter une autre variable
KEY_PATTERN = re.compile(r"^sk-or-[A-Za-z0-9_-]{10,200}$")
MODEL_PATTERN = re.compile(r"^[A-Za-z0-9._-]+/[A-Za-z0-9._:-]+$")


class AISettingsRequest(BaseModel):
    model: str = Field(min_length=3, max_length=100)
    # Vide : la clé actuelle est conservée
    api_key: str = Field(default="", max_length=250)


def _view(settings: Settings) -> dict:
    key = settings.openrouter_api_key
    return {
        "model": settings.openrouter_model,
        "key_configured": bool(key),
        "key_hint": f"…{key[-4:]}" if len(key) >= 12 else "",
        "ai_enabled": settings.ai_enabled,
        "ai_disabled": settings.secuscan_ai_disabled,
        "price_input_per_mtok": settings.secuscan_ai_price_input_per_mtok,
        "price_output_per_mtok": settings.secuscan_ai_price_output_per_mtok,
    }


def _parse_catalog(body: dict) -> list[dict]:
    """Modèles OpenRouter, tarifs convertis en $ par million de jetons ; les routeurs à prix variable sont écartés."""
    models = []
    for m in body.get("data", []):
        try:
            model_id = str(m["id"])
            price_in = float(m["pricing"]["prompt"]) * 1_000_000
            price_out = float(m["pricing"]["completion"]) * 1_000_000
        except (KeyError, TypeError, ValueError):
            continue
        if price_in < 0 or price_out < 0 or not MODEL_PATTERN.match(model_id):
            continue
        models.append({
            "id": model_id, "name": str(m.get("name") or model_id), "provider": model_id.split("/", 1)[0],
            "price_input_per_mtok": round(price_in, 4), "price_output_per_mtok": round(price_out, 4),
            "context_length": m.get("context_length"),
        })
    return sorted(models, key=lambda m: (m["provider"] != "anthropic", m["provider"], m["name"].lower()))


def model_catalog(settings: Settings) -> list[dict]:
    """Catalogue gardé une heure en mémoire ; liste vide si OpenRouter est injoignable ou en mode hors ligne."""
    if settings.secuscan_offline:
        return []
    with _catalog_lock:
        if _catalog["models"] and time.time() - _catalog["fetched_at"] < CATALOG_TTL_SECONDS:
            return _catalog["models"]
        try:
            with httpx.Client(timeout=15) as client:
                resp = client.get(settings.openrouter_models_url)
            resp.raise_for_status()
            models = _parse_catalog(resp.json())
        except (httpx.HTTPError, ValueError) as exc:
            log.warning("Catalogue OpenRouter indisponible : %s", exc)
            return _catalog["models"]
        _catalog.update(models=models, fetched_at=time.time())
        return models


def _write_env(path: Path, values: dict[str, str]) -> None:
    """Remplace ou ajoute les variables, en gardant les autres lignes du fichier."""
    lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    names = {name.upper() for name in values}
    kept = [line for line in lines if line.split("=", 1)[0].strip().upper() not in names]
    kept += [f"{name}={value}" for name, value in values.items()]
    tmp = path.with_name(path.name + ".tmp")
    # UTF-8 sans BOM : un BOM rendrait la première variable illisible
    tmp.write_text("\n".join(kept) + "\n", encoding="utf-8")
    os.replace(tmp, path)


@router.get("/ai")
def get_ai_settings(_: Context = Depends(require_installation_admin), service: ScanService = Depends(get_service)):
    return _view(service.settings)


@router.get("/ai/models")
def list_models(_: Context = Depends(require_installation_admin), service: ScanService = Depends(get_service)):
    return model_catalog(service.settings)


@router.put("/ai")
def update_ai_settings(body: AISettingsRequest, ctx: Context = Depends(require_installation_admin),
                       service: ScanService = Depends(get_service)):
    settings = service.settings
    model = body.model.strip()
    key = body.api_key.strip()
    if not MODEL_PATTERN.match(model):
        raise HTTPException(400, "Identifiant de modèle invalide (format attendu : fournisseur/modèle).")
    if key and not KEY_PATTERN.match(key):
        raise HTTPException(400, "Clé invalide : une clé OpenRouter commence par sk-or-.")

    candidate = settings.model_copy(
        update={"openrouter_model": model, "openrouter_api_key": key or settings.openrouter_api_key})
    if candidate.openrouter_api_key:
        try:
            enricher.check_connection(candidate)
        except enricher.AIUnavailable as exc:
            raise HTTPException(400, f"Non enregistré : {exc}") from exc

    values = {"OPENROUTER_MODEL": model}
    if key:
        values["OPENROUTER_API_KEY"] = key
    # Tarif du modèle choisi (catalogue OpenRouter) : l'estimation des coûts IA reste juste
    entry = next((m for m in model_catalog(settings) if m["id"] == model), None)
    if entry:
        values["SECUSCAN_AI_PRICE_INPUT_PER_MTOK"] = str(entry["price_input_per_mtok"])
        values["SECUSCAN_AI_PRICE_OUTPUT_PER_MTOK"] = str(entry["price_output_per_mtok"])
    _write_env(settings.secuscan_env_file, values)
    # Application immédiate : les analyses suivantes utilisent la nouvelle clé et le nouveau modèle
    settings.openrouter_model = model
    if key:
        settings.openrouter_api_key = key
    if entry:
        settings.secuscan_ai_price_input_per_mtok = entry["price_input_per_mtok"]
        settings.secuscan_ai_price_output_per_mtok = entry["price_output_per_mtok"]
    service.storage.audit("settings.ai_updated", "openrouter", {"model": model, "key_changed": bool(key)},
                          org_id=ctx.org_id, actor=ctx.email)
    return _view(settings)
