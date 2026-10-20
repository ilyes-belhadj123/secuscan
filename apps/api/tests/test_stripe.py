"""SS-20 — paiement Stripe (API Stripe simulée, clés factices)."""
import hashlib
import hmac
import json
import time
from urllib.parse import parse_qs

import httpx
import pytest
from conftest import register

from secuscan import stripe_billing
from secuscan.stripe_billing import verify_stripe_signature

WHSEC = "whsec_placeholder"


class FakeStripe:
    def __init__(self):
        self.calls: list[tuple[str, str, dict]] = []
        self.quantity = 1

    def handler(self, request: httpx.Request) -> httpx.Response:
        data = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
        self.calls.append((request.method, request.url.path, data))
        path = request.url.path
        if path.endswith("/checkout/sessions"):
            return httpx.Response(200, json={"id": "cs_1", "url": "https://checkout.stripe.com/c/pay/cs_1"})
        if path.endswith("/subscriptions/sub_1") and request.method == "GET":
            return httpx.Response(200, json={"items": {"data": [{"id": "si_1", "quantity": self.quantity}]}})
        if path.endswith("/subscriptions/sub_1") and request.method == "POST":
            self.quantity = int(data.get("items[0][quantity]", self.quantity))
            return httpx.Response(200, json={"id": "sub_1"})
        if path.endswith("/subscriptions/sub_1") and request.method == "DELETE":
            return httpx.Response(200, json={"id": "sub_1", "status": "canceled"})
        if path.endswith("/billing_portal/sessions"):
            return httpx.Response(200, json={"url": "https://billing.stripe.com/p/session/1"})
        return httpx.Response(404, json={"error": {"message": "inconnu"}})


@pytest.fixture
def stripe(service, monkeypatch):
    s = service.settings
    s.secuscan_stripe_secret_key = "sk_test_placeholder"
    s.secuscan_stripe_webhook_secret = WHSEC
    s.secuscan_stripe_price_pro, s.secuscan_stripe_price_business = "price_pro", "price_business"
    s.secuscan_first_org_plan = "free"
    fake = FakeStripe()
    monkeypatch.setattr(stripe_billing, "_client", lambda settings: httpx.Client(
        base_url="https://api.stripe.com/v1", transport=httpx.MockTransport(fake.handler)))
    return fake


def _signed(client, event: dict, secret: str = WHSEC, ts: int | None = None):
    body = json.dumps(event).encode()
    ts = ts or int(time.time())
    sig = hmac.new(secret.encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    return client.post("/api/billing/stripe/webhook", content=body,
                       headers={"Stripe-Signature": f"t={ts},v1={sig}", "Content-Type": "application/json"})


def test_signature_checks():
    body, ts = b'{"id": "evt_1"}', int(time.time())
    good = hmac.new(WHSEC.encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    assert verify_stripe_signature(WHSEC, body, f"t={ts},v1={good}")
    assert not verify_stripe_signature(WHSEC, body + b" ", f"t={ts},v1={good}")  # corps modifié
    assert not verify_stripe_signature(WHSEC, body, f"t={ts - 600},v1={good}")  # trop ancien (rejeu)
    assert not verify_stripe_signature(WHSEC, body, None)


def test_checkout_then_webhook_activates_plan(api, service, stripe):
    owner = register(api(), "jane.doe@example.com")
    org_id = owner.get("/api/auth/me").json()["org"]["id"]
    resp = owner.post("/api/billing/plan", json={"plan": "pro"}).json()
    assert resp["checkout_url"].startswith("https://checkout.stripe.com/")
    method, path, data = stripe.calls[-1]
    assert data["line_items[0][price]"] == "price_pro" and data["metadata[org_id]"] == org_id
    assert data["customer_email"] == "jane.doe@example.com"
    # Le retour du navigateur ne suffit pas : l'offre ne change qu'avec l'événement signé
    assert owner.get("/api/billing").json()["plan"] == "free"

    event = {"id": "evt_1", "type": "checkout.session.completed", "data": {"object": {
        "mode": "subscription", "customer": "cus_1", "subscription": "sub_1",
        "metadata": {"org_id": org_id, "plan": "pro"}}}}
    assert _signed(owner, event).status_code == 200
    billing = owner.get("/api/billing").json()
    assert billing["plan"] == "pro" and billing["provider"] == "stripe" and billing["has_subscription"]
    assert billing["invoices"] == []  # les factures sont émises par Stripe
    assert _signed(owner, event).json() == {"duplicate": True}  # renvoi du même événement : ignoré

    # Pro → Business : changement de tarif au prorata, sans repasser par le paiement
    assert owner.post("/api/billing/plan", json={"plan": "business"}).json()["ok"]
    assert stripe.calls[-1][2]["items[0][price]"] == "price_business"
    assert owner.get("/api/billing").json()["plan"] == "business"

    # Portail client
    assert owner.post("/api/billing/portal").json()["url"].startswith("https://billing.stripe.com/")

    # Résiliation côté Stripe → retour à Free
    _signed(owner, {"id": "evt_2", "type": "customer.subscription.deleted",
                    "data": {"object": {"id": "sub_1", "metadata": {"org_id": org_id}}}})
    assert owner.get("/api/billing").json()["plan"] == "free"


def test_forged_or_unsigned_webhook_rejected(api, service, stripe):
    owner = register(api(), "jane.doe@example.com")
    org_id = owner.get("/api/auth/me").json()["org"]["id"]
    event = {"id": "evt_x", "type": "checkout.session.completed", "data": {"object": {
        "mode": "subscription", "metadata": {"org_id": org_id, "plan": "business"}}}}
    assert _signed(owner, event, secret="whsec_attaquant").status_code == 401
    assert owner.post("/api/billing/stripe/webhook", json=event).status_code == 401
    assert owner.get("/api/billing").json()["plan"] == "free"


def test_seats_follow_members(api, service, stripe):
    owner = register(api(), "jane.doe@example.com")
    org_id = owner.get("/api/auth/me").json()["org"]["id"]
    service.storage.set_org_plan(org_id, "pro")
    service.storage.set_stripe_ids(org_id, "cus_1", "sub_1")
    inv = owner.post("/api/org/invitations", json={"email": "john.doe@example.com", "role": "member"}).json()
    member = register(api(), "john.doe@example.com", org_name=None, invitation_token=inv["url"].rsplit("/", 1)[1])
    assert stripe.quantity == 2
    member_id = member.get("/api/auth/me").json()["user"]["id"]
    owner.delete(f"/api/org/members/{member_id}")
    assert stripe.quantity == 1


def test_downgrade_to_free_cancels_subscription(api, service, stripe):
    owner = register(api(), "jane.doe@example.com")
    org_id = owner.get("/api/auth/me").json()["org"]["id"]
    service.storage.set_org_plan(org_id, "pro")
    service.storage.set_stripe_ids(org_id, "cus_1", "sub_1")
    assert owner.post("/api/billing/plan", json={"plan": "free"}).json()["ok"]
    assert ("DELETE", "/v1/subscriptions/sub_1") in [(m, p) for m, p, _ in stripe.calls]
    assert owner.get("/api/billing").json()["plan"] == "free" and not service.storage.stripe_ids(org_id)[1]


def test_stripe_error_is_reported(api, service, stripe, monkeypatch):
    monkeypatch.setattr(stripe_billing, "_client", lambda settings: httpx.Client(
        base_url="https://api.stripe.com/v1",
        transport=httpx.MockTransport(lambda r: httpx.Response(400, json={"error": {"message": "Tarif inconnu"}}))))
    owner = register(api(), "jane.doe@example.com")
    resp = owner.post("/api/billing/plan", json={"plan": "pro"})
    assert resp.status_code == 502 and "Tarif inconnu" in resp.json()["detail"]
