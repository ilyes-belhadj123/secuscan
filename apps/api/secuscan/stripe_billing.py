"""SS-20 — paiement réel avec Stripe (abonnement mensuel facturé par membre).

- Passage à une offre payante sans abonnement : page de paiement Stripe Checkout ; l'offre n'est
  activée qu'à la réception de l'événement signé `checkout.session.completed`, jamais au retour
  du navigateur (qui peut être falsifié).
- Pro ↔ Business avec un abonnement : changement de tarif au prorata ; retour à Free : résiliation.
- Le nombre de sièges suit les arrivées et départs de membres.
- Moyen de paiement, factures et résiliation : portail client Stripe.
- Webhook : signature `Stripe-Signature` vérifiée (HMAC-SHA256, 5 minutes de tolérance), chaque
  événement n'est traité qu'une fois.
Les numéros de carte ne transitent jamais par SecuScan.
"""
import hashlib
import hmac
import json
import logging
import time

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request

from .billing import change_plan, ensure_fits, usage
from .config import Settings
from .deps import Context, current_context, get_service
from .pipeline import ScanService
from .plans import QuotaExceeded

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/billing")
PROVIDER = "Stripe"
SIGNATURE_TOLERANCE_SECONDS = 300
ACTIVE = {"active", "trialing"}
ENDED = {"canceled", "unpaid", "incomplete_expired"}


class StripeError(RuntimeError):
    pass


def _client(settings: Settings) -> httpx.Client:
    return httpx.Client(base_url=settings.secuscan_stripe_api_url, timeout=30,
                        headers={"Authorization": f"Bearer {settings.secuscan_stripe_secret_key}"})


def _call(settings: Settings, method: str, path: str, data: dict | None = None) -> dict:
    try:
        with _client(settings) as client:
            resp = client.request(method, path, data=data)
    except httpx.HTTPError as exc:
        raise StripeError(f"Stripe injoignable : {exc}") from exc
    if not resp.is_success:
        try:
            message = resp.json()["error"]["message"]
        except (ValueError, KeyError, TypeError):
            message = f"code {resp.status_code}"
        raise StripeError(f"Stripe a refusé la demande : {message}")
    return resp.json()


def price_for(settings: Settings, plan: str) -> str:
    return {"pro": settings.secuscan_stripe_price_pro, "business": settings.secuscan_stripe_price_business}[plan]


def plan_for_price(settings: Settings, price_id: str) -> str | None:
    return {settings.secuscan_stripe_price_pro: "pro", settings.secuscan_stripe_price_business: "business"}.get(price_id)


def _seats(service: ScanService, org_id: str) -> int:
    return max(1, usage(service.storage, org_id)["members"])


def _first_item(settings: Settings, subscription_id: str) -> dict:
    return _call(settings, "GET", f"/subscriptions/{subscription_id}")["items"]["data"][0]


def request_plan_change(service: ScanService, ctx: Context, plan: str) -> dict:
    """Demande de changement d'offre du propriétaire : URL de paiement, ou changement appliqué."""
    settings, storage = service.settings, service.storage
    ensure_fits(storage, ctx.org_id, plan)
    customer_id, subscription_id = storage.stripe_ids(ctx.org_id)
    try:
        if plan == "free":
            if subscription_id:
                _call(settings, "DELETE", f"/subscriptions/{subscription_id}")
                storage.set_stripe_ids(ctx.org_id, customer_id, "")
            change_plan(service, ctx.org_id, "free", ctx.email, provider=PROVIDER, invoice=False)
            return {"ok": True, "invoice": None}
        if subscription_id:
            item = _first_item(settings, subscription_id)
            _call(settings, "POST", f"/subscriptions/{subscription_id}", {
                "items[0][id]": item["id"], "items[0][price]": price_for(settings, plan),
                "items[0][quantity]": _seats(service, ctx.org_id), "proration_behavior": "create_prorations",
                "metadata[org_id]": ctx.org_id, "metadata[plan]": plan,
            })
            change_plan(service, ctx.org_id, plan, ctx.email, provider=PROVIDER, invoice=False)
            return {"ok": True, "invoice": None}
        base = settings.secuscan_public_url.rstrip("/")
        data = {
            "mode": "subscription", "client_reference_id": ctx.org_id,
            "line_items[0][price]": price_for(settings, plan), "line_items[0][quantity]": _seats(service, ctx.org_id),
            "success_url": f"{base}/offre?paiement=ok", "cancel_url": f"{base}/offre?paiement=annule",
            "metadata[org_id]": ctx.org_id, "metadata[plan]": plan,
            "subscription_data[metadata][org_id]": ctx.org_id, "subscription_data[metadata][plan]": plan,
            "locale": "fr",
        }
        data.update({"customer": customer_id} if customer_id else {"customer_email": ctx.email})
        session = _call(settings, "POST", "/checkout/sessions", data)
    except StripeError as exc:
        raise HTTPException(502, str(exc)) from exc
    storage.audit("billing.checkout_started", ctx.org_id, {"plan": plan}, org_id=ctx.org_id, actor=ctx.email)
    return {"ok": True, "invoice": None, "checkout_url": session["url"]}


def sync_seats(service: ScanService, org_id: str) -> None:
    """Après l'arrivée ou le départ d'un membre : quantité de l'abonnement = nombre de membres."""
    settings = service.settings
    _customer, subscription_id = service.storage.stripe_ids(org_id)
    if not (settings.stripe_enabled and subscription_id):
        return
    try:
        item = _first_item(settings, subscription_id)
        if item.get("quantity") != _seats(service, org_id):
            _call(settings, "POST", f"/subscriptions/{subscription_id}", {
                "items[0][id]": item["id"], "items[0][quantity]": _seats(service, org_id),
                "proration_behavior": "create_prorations",
            })
    except (StripeError, KeyError, IndexError) as exc:
        # Ne bloque jamais la gestion de l'équipe ; l'écart est signalé pour régularisation
        log.warning("Sièges Stripe non synchronisés pour %s : %s", org_id, exc)


def verify_stripe_signature(secret: str, body: bytes, header: str | None, now: float | None = None) -> bool:
    if not (secret and header):
        return False
    parts = [p.split("=", 1) for p in header.split(",") if "=" in p]
    timestamp = next((v for k, v in parts if k.strip() == "t"), "")
    signatures = [v for k, v in parts if k.strip() == "v1"]
    if not timestamp.isdigit() or not signatures:
        return False
    if abs((now or time.time()) - int(timestamp)) > SIGNATURE_TOLERANCE_SECONDS:
        return False  # événement trop ancien : protection contre le rejeu
    expected = hmac.new(secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()
    return any(hmac.compare_digest(expected, s) for s in signatures)


@router.post("/portal")
def portal(ctx: Context = Depends(current_context), service: ScanService = Depends(get_service)):
    """Portail client Stripe : moyen de paiement, factures, résiliation (propriétaire)."""
    if ctx.role != "owner":
        raise HTTPException(403, "Seul le propriétaire de l'organisation gère le paiement.")
    customer_id, _ = service.storage.stripe_ids(ctx.org_id)
    if not (service.settings.stripe_enabled and customer_id):
        raise HTTPException(404, "Aucun abonnement Stripe pour cette organisation")
    try:
        session = _call(service.settings, "POST", "/billing_portal/sessions", {
            "customer": customer_id, "return_url": f"{service.settings.secuscan_public_url.rstrip('/')}/offre",
        })
    except StripeError as exc:
        raise HTTPException(502, str(exc)) from exc
    return {"url": session["url"]}


@router.post("/stripe/webhook")
async def stripe_webhook(request: Request, service: ScanService = Depends(get_service)):
    settings, storage = service.settings, service.storage
    body = await request.body()
    if not verify_stripe_signature(settings.secuscan_stripe_webhook_secret, body, request.headers.get("stripe-signature")):
        raise HTTPException(401, "Signature invalide")
    event = json.loads(body)
    if not storage.first_stripe_event(str(event.get("id", ""))):
        return {"duplicate": True}
    kind, obj = event.get("type"), (event.get("data") or {}).get("object") or {}
    org_id = str((obj.get("metadata") or {}).get("org_id") or obj.get("client_reference_id") or "")
    if not storage.get_org(org_id):
        return {"ignored": True}
    customer_id, subscription_id = storage.stripe_ids(org_id)
    try:
        if kind == "checkout.session.completed" and obj.get("mode") == "subscription":
            plan = str((obj.get("metadata") or {}).get("plan", ""))
            storage.set_stripe_ids(org_id, str(obj.get("customer") or customer_id), str(obj.get("subscription") or ""))
            if plan in ("pro", "business"):
                change_plan(service, org_id, plan, actor="Stripe", provider=PROVIDER, invoice=False)
        elif kind == "customer.subscription.updated":
            price = (((obj.get("items") or {}).get("data") or [{}])[0].get("price") or {}).get("id", "")
            plan = plan_for_price(settings, price)
            current = storage.get_org(org_id)["plan"]
            if obj.get("status") in ACTIVE and plan and plan != current:
                change_plan(service, org_id, plan, actor="Stripe", provider=PROVIDER, invoice=False)
            elif obj.get("status") in ENDED and current != "free":
                change_plan(service, org_id, "free", actor="Stripe", provider=PROVIDER, invoice=False)
        elif kind == "customer.subscription.deleted":
            storage.set_stripe_ids(org_id, customer_id, "")
            if storage.get_org(org_id)["plan"] != "free":
                change_plan(service, org_id, "free", actor="Stripe", provider=PROVIDER, invoice=False)
        elif kind == "invoice.payment_failed":
            storage.audit("billing.payment_failed", org_id, {"invoice": obj.get("id")}, org_id=org_id, actor="Stripe")
    except QuotaExceeded as exc:
        # Paiement reçu mais usage incompatible (ex. membres ajoutés entre-temps) : à régulariser à la main
        storage.audit("billing.plan_change_refused", org_id, {"reason": str(exc)}, org_id=org_id, actor="Stripe")
    return {"ok": True}
