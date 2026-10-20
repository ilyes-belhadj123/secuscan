"""SS-20 — offres, quotas et facturation.

Trois modes :
- Stripe (variables SECUSCAN_STRIPE_*) : paiement réel, voir stripe_billing.py ;
- webhook générique signé HMAC-SHA256 (`/api/billing/webhook`) pour un autre prestataire ;
- démo (par défaut) : changement d'offre immédiat et facture pro forma, sans paiement.
"""
import hashlib
import hmac
import json
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from .deps import Context, current_context, get_service
from .pipeline import ScanService
from .plans import FEATURE_LABELS, PLAN_ORDER, PLANS, QUOTA_EXEMPT_PROJECTS, QuotaExceeded, get_plan
from .storage import Storage

router = APIRouter(prefix="/api/billing")
DEMO_PROVIDER = "démo (sans paiement)"


def month_start_iso(now: datetime | None = None) -> str:
    now = now or datetime.now(UTC)
    return now.replace(day=1, hour=0, minute=0, second=0, microsecond=0).isoformat()


def usage(storage: Storage, org_id: str) -> dict:
    projects = storage.project_names(org_id) - QUOTA_EXEMPT_PROJECTS
    return {
        "scans_this_month": storage.count_scans_since(org_id, month_start_iso()),
        "projects": len(projects),
        "members": len(storage.list_members(org_id)),
        "pending_invitations": len(storage.list_invitations(org_id)),
    }


def check_scan_quota(storage: Storage, org_id: str, project_name: str) -> None:
    org = storage.get_org(org_id)
    plan = get_plan(org["plan"] if org else None)
    u = usage(storage, org_id)
    if plan.monthly_scans is not None and u["scans_this_month"] >= plan.monthly_scans:
        raise QuotaExceeded(
            f"Quota atteint : {plan.monthly_scans} analyses par mois avec l'offre {plan.name}. "
            "Passez à une offre supérieure pour continuer ce mois-ci."
        )
    known = storage.project_names(org_id)
    if (plan.projects is not None and project_name not in known and project_name not in QUOTA_EXEMPT_PROJECTS
            and u["projects"] >= plan.projects):
        raise QuotaExceeded(
            f"L'offre {plan.name} est limitée à {plan.projects} projet(s). Analysez à nouveau un projet existant "
            "ou passez à une offre supérieure."
        )


def check_member_quota(storage: Storage, org_id: str) -> None:
    org = storage.get_org(org_id)
    plan = get_plan(org["plan"] if org else None)
    u = usage(storage, org_id)
    if plan.members is not None and u["members"] + u["pending_invitations"] >= plan.members:
        raise QuotaExceeded(
            f"L'offre {plan.name} est limitée à {plan.members} membres (invitations en attente comprises)."
        )


def ensure_fits(storage: Storage, org_id: str, new_plan: str) -> None:
    """QuotaExceeded si l'usage actuel de l'organisation dépasse les limites de l'offre visée."""
    plan = get_plan(new_plan)
    u = usage(storage, org_id)
    if plan.members is not None and u["members"] > plan.members:
        raise QuotaExceeded(
            f"L'offre {plan.name} est limitée à {plan.members} membres : retirez d'abord "
            f"{u['members'] - plan.members} membre(s)."
        )


def change_plan(service: ScanService, org_id: str, new_plan: str, actor: str, provider: str = DEMO_PROVIDER,
                invoice: bool = True) -> dict | None:
    """Applique une nouvelle offre après vérification que l'usage actuel y tient. Renvoie la facture émise.

    `invoice=False` : la facture est émise par le prestataire (Stripe), pas par SecuScan.
    """
    storage = service.storage
    org = storage.get_org(org_id)
    ensure_fits(storage, org_id, new_plan)
    u = usage(storage, org_id)
    previous = org["plan"]
    storage.set_org_plan(org_id, new_plan)
    created = None
    price = service.settings.price_per_member(new_plan)
    if invoice and price > 0:
        period = datetime.now(UTC).strftime("%Y-%m")
        status = "pro forma (mode démo)" if provider == DEMO_PROVIDER else "payée"
        created = storage.create_invoice(org_id, period, new_plan, max(1, u["members"]), price, status, provider)
    storage.audit("billing.plan_changed", org_id, {"from": previous, "to": new_plan, "provider": provider},
                  org_id=org_id, actor=actor)
    return created


def verify_signature(secret: str, body: bytes, header: str | None) -> bool:
    if not (secret and header and header.startswith("sha256=")):
        return False
    expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, header.removeprefix("sha256="))


# ---------------------------------------------------------------------- API
class PlanRequest(BaseModel):
    plan: str = Field(pattern="^(free|pro|business)$")


def _catalog(service: ScanService) -> list[dict]:
    settings = service.settings
    out = []
    for plan_id in PLAN_ORDER:
        p = PLANS[plan_id]
        calls, _tokens = settings.ai_budget_for(plan_id)
        out.append({
            "id": p.id, "name": p.name, "tagline": p.tagline,
            "price_per_member_eur": settings.price_per_member(plan_id),
            "monthly_scans": p.monthly_scans, "projects": p.projects, "members": p.members,
            "ai_calls_per_scan": calls,
            "features": [FEATURE_LABELS[f] for f in sorted(p.features) if f in FEATURE_LABELS],
        })
    return out


@router.get("")
def billing(ctx: Context = Depends(current_context), service: ScanService = Depends(get_service)):
    storage = service.storage
    org = storage.get_org(ctx.org_id)
    plan = get_plan(org["plan"])
    u = usage(storage, ctx.org_id)
    price = service.settings.price_per_member(plan.id)
    return {
        "plan": plan.id, "plan_name": plan.name, "usage": u,
        "limits": {"monthly_scans": plan.monthly_scans, "projects": plan.projects, "members": plan.members},
        "monthly_estimate_eur": round(price * max(1, u["members"]), 2) if price else 0.0,
        "catalog": _catalog(service),
        "invoices": storage.list_invoices(ctx.org_id) if ctx.is_admin else [],
        "provider": ("stripe" if service.settings.stripe_enabled
                     else "webhook" if service.settings.secuscan_billing_webhook_secret else "demo"),
        "has_subscription": bool(storage.stripe_ids(ctx.org_id)[1]),
        "can_manage": ctx.role == "owner",
    }


@router.post("/plan")
def select_plan(body: PlanRequest, ctx: Context = Depends(current_context), service: ScanService = Depends(get_service)):
    if ctx.role != "owner":
        raise HTTPException(403, "Seul le propriétaire de l'organisation peut changer d'offre.")
    try:
        if service.settings.stripe_enabled:
            from .stripe_billing import request_plan_change  # import local : stripe_billing dépend de ce module
            return request_plan_change(service, ctx, body.plan)
        invoice = change_plan(service, ctx.org_id, body.plan, ctx.email)
    except QuotaExceeded as exc:
        raise HTTPException(409, str(exc)) from exc
    return {"ok": True, "invoice": invoice}


@router.post("/webhook")
async def webhook(request: Request, service: ScanService = Depends(get_service)):
    """Événement du prestataire de paiement, signé : {"type": "subscription.updated", "org_id", "plan"}."""
    secret = service.settings.secuscan_billing_webhook_secret
    body = await request.body()
    if not verify_signature(secret, body, request.headers.get("x-secuscan-signature")):
        raise HTTPException(401, "Signature invalide")
    try:
        event = json.loads(body)
    except json.JSONDecodeError as exc:
        raise HTTPException(400, "Corps JSON invalide") from exc
    if event.get("type") != "subscription.updated":
        return {"ignored": True}
    org_id, plan = str(event.get("org_id", "")), str(event.get("plan", ""))
    if plan not in PLANS or not service.storage.get_org(org_id):
        raise HTTPException(400, "Organisation ou offre inconnue")
    try:
        change_plan(service, org_id, plan, actor="prestataire de paiement", provider=str(event.get("provider", "webhook")))
    except QuotaExceeded as exc:
        raise HTTPException(409, str(exc)) from exc
    return {"ok": True}
