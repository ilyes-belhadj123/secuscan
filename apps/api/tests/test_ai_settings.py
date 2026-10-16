"""Paramètres IA depuis l'interface : clé OpenRouter et modèle."""
import pytest
from conftest import register

from secuscan import ai_settings
from secuscan.ai import enricher

FAKE_KEY = "sk-or-v1-" + "0" * 60 + "abcd"


@pytest.fixture
def no_network(monkeypatch):
    calls = []
    monkeypatch.setattr(enricher, "check_connection", lambda settings: calls.append(
        (settings.openrouter_api_key, settings.openrouter_model)))
    return calls


def test_update_key_and_model(api, service, no_network):
    service.settings.secuscan_env_file.write_text("SECUSCAN_PLAN=pro\nOPENROUTER_MODEL=old/model\n", encoding="utf-8")
    client = register(api(), "jane.doe@example.com")
    assert client.get("/api/auth/me").json()["can_manage_settings"] is True

    resp = client.put("/api/settings/ai", json={"model": "anthropic/claude-opus-5.5", "api_key": FAKE_KEY})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert {k: body[k] for k in ("model", "key_configured", "key_hint", "ai_enabled")} == {
        "model": "anthropic/claude-opus-5.5", "key_configured": True, "key_hint": "…abcd", "ai_enabled": True}
    assert FAKE_KEY not in resp.text  # la clé n'est jamais renvoyée
    assert no_network == [(FAKE_KEY, "anthropic/claude-opus-5.5")]
    # Appliqué sans redémarrage et enregistré dans .env, les autres variables conservées
    assert service.settings.openrouter_api_key == FAKE_KEY
    env = service.settings.secuscan_env_file.read_text(encoding="utf-8").splitlines()
    assert sorted(env) == sorted(["SECUSCAN_PLAN=pro", "OPENROUTER_MODEL=anthropic/claude-opus-5.5",
                                  f"OPENROUTER_API_KEY={FAKE_KEY}"])
    entry = client.get("/api/audit").json()[0]
    assert entry["action"] == "settings.ai_updated" and FAKE_KEY not in str(entry)


def test_model_only_keeps_key(api, service, no_network):
    service.settings.openrouter_api_key = FAKE_KEY
    client = register(api(), "jane.doe@example.com")
    resp = client.put("/api/settings/ai", json={"model": "anthropic/claude-haiku-5.5"})
    assert resp.status_code == 200
    assert service.settings.openrouter_api_key == FAKE_KEY
    assert "OPENROUTER_API_KEY" not in service.settings.secuscan_env_file.read_text(encoding="utf-8")


def test_failed_connection_saves_nothing(api, service, monkeypatch):
    def refuse(settings):
        raise enricher.AIUnavailable("Clé OpenRouter refusée.")
    monkeypatch.setattr(enricher, "check_connection", refuse)
    client = register(api(), "jane.doe@example.com")
    resp = client.put("/api/settings/ai", json={"model": "anthropic/claude-sonnet-5", "api_key": FAKE_KEY})
    assert resp.status_code == 400 and "refusée" in resp.json()["detail"]
    assert service.settings.openrouter_api_key == ""
    assert not service.settings.secuscan_env_file.exists()


@pytest.mark.parametrize("body", [
    {"model": "anthropic/claude\nSECUSCAN_PLAN=business"},
    {"model": "sans-fournisseur"},
    {"model": "anthropic/claude-sonnet-5", "api_key": "pas-une-cle"},
    {"model": "anthropic/claude-sonnet-5", "api_key": "sk-or-v1-abc\nSECUSCAN_PLAN=business"},
])
def test_rejects_invalid_values(api, service, no_network, body):
    client = register(api(), "jane.doe@example.com")
    assert client.put("/api/settings/ai", json=body).status_code == 400
    assert not service.settings.secuscan_env_file.exists() and not no_network


def test_reserved_to_installation_admins(api, service, no_network):
    owner = register(api(), "jane.doe@example.com")
    resp = owner.post("/api/org/invitations", json={"email": "john.doe@example.com", "role": "member"})
    member = register(api(), "john.doe@example.com", org_name=None, invitation_token=resp.json()["url"].rsplit("/", 1)[1])
    other_org_owner = register(api(), "bob@example.com", org_name="Globex")
    for client in (member, other_org_owner):
        assert client.get("/api/auth/me").json()["can_manage_settings"] is False
        assert client.get("/api/settings/ai").status_code == 403
        assert client.put("/api/settings/ai", json={"model": "anthropic/claude-sonnet-5"}).status_code == 403
    # Un opérateur de la plateforme y a accès, quelle que soit son organisation
    service.settings.secuscan_operator_emails = ["bob@example.com"]
    assert other_org_owner.get("/api/settings/ai").status_code == 200


CATALOG = {"data": [
    {"id": "openai/gpt-x", "name": "GPT X", "pricing": {"prompt": "0.000001", "completion": "0.000004"},
     "context_length": 128000},
    {"id": "anthropic/claude-haiku-5.5", "name": "Claude Haiku 5.5",
     "pricing": {"prompt": "0.0000008", "completion": "0.000004"}, "context_length": 200000},
    {"id": "openrouter/auto", "name": "Auto", "pricing": {"prompt": "-1", "completion": "-1"}},
    {"id": "broken/model", "name": "Sans tarif"},
]}


def test_catalog_parsing():
    models = ai_settings._parse_catalog(CATALOG)
    assert [m["id"] for m in models] == ["anthropic/claude-haiku-5.5", "openai/gpt-x"]  # Anthropic en tête
    assert models[0]["price_input_per_mtok"] == 0.8 and models[0]["price_output_per_mtok"] == 4.0


def test_catalog_offline_is_empty(api, service):
    client = register(api(), "jane.doe@example.com")
    assert client.get("/api/settings/ai/models").json() == []


def test_choosing_model_applies_its_price(api, service, no_network, monkeypatch):
    monkeypatch.setattr(ai_settings, "model_catalog", lambda settings: ai_settings._parse_catalog(CATALOG))
    client = register(api(), "jane.doe@example.com")
    body = client.put("/api/settings/ai", json={"model": "anthropic/claude-haiku-5.5"}).json()
    assert body["price_input_per_mtok"] == 0.8 and body["price_output_per_mtok"] == 4.0
    assert service.settings.secuscan_ai_price_input_per_mtok == 0.8
    env = service.settings.secuscan_env_file.read_text(encoding="utf-8")
    assert "SECUSCAN_AI_PRICE_INPUT_PER_MTOK=0.8" in env and "SECUSCAN_AI_PRICE_OUTPUT_PER_MTOK=4.0" in env
