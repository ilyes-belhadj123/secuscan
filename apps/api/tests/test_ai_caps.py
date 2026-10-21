"""Plafonds de coût IA : par organisation et par mois, pour toute l'installation, mode formation, inscriptions."""
import pytest
from conftest import PASSWORD, register

from secuscan.ai.enricher import Enricher
from secuscan.models import Scan, now_iso
from secuscan.pipeline import new_id
from secuscan.training_exercises import EXERCISES_BY_ID

MONTH = now_iso()[:8] + "01"


def fake_ai(monkeypatch, calls: list):
    def complete(self, prompt, **kw):
        self.budget.reserve()  # comme le vrai transport : refus si le budget est épuisé
        calls.append(prompt)
        self.stats.add(call=True, prompt_tokens=1000, completion_tokens=200)
        return {"verdict": "true_positive", "confidence": 0.9, "findings": [], "fixed": True, "feedback": "Bien."}
    monkeypatch.setattr(Enricher, "_complete", complete)


def scan_project(service, tmp_path, org_id="org-1"):
    project = tmp_path / "p"
    project.mkdir(exist_ok=True)
    (project / "app.py").write_text("import os\nos.system(cmd)\n", encoding="utf-8")
    scan = Scan(id=new_id(), project_name="Acme", source="upload", org_id=org_id, plan="free")
    service.storage.save_scan(scan)
    service.run(scan, project)
    return scan


def test_usage_is_recorded_and_monthly_cap_stops_ai(service, tmp_path, monkeypatch):
    service.settings.openrouter_api_key = "sk-or-placeholder"
    calls: list = []
    fake_ai(monkeypatch, calls)
    scan = scan_project(service, tmp_path)
    used = service.storage.ai_tokens_since(MONTH, "org-1")
    assert calls and used == scan.summary.ai_tokens > 0

    # Plafond de l'offre Free atteint : l'analyse suivante se fait sans IA, et le dit
    service.storage.add_ai_usage("org-1", "scan", service.settings.ai_monthly_tokens_for("free"), 1, 1.0)
    calls.clear()
    capped = scan_project(service, tmp_path)
    assert not calls and any("Plafond mensuel" in w for w in capped.summary.warnings)
    # Une autre organisation n'est pas concernée
    assert service.ai_allowance("org-2", "free")[0] > 0


def test_installation_cap_protects_the_api_key(service):
    service.settings.secuscan_ai_monthly_tokens_total = 50_000
    service.storage.add_ai_usage("org-a", "scan", 30_000, 3, 0.1)
    service.storage.add_ai_usage("org-b", "scan", 20_000, 2, 0.1)
    remaining, reason = service.ai_allowance("org-c", "business")
    assert remaining == 0 and "plateforme" in reason


def test_usage_recorded_even_when_the_scan_fails(service, tmp_path, monkeypatch):
    service.settings.openrouter_api_key = "sk-or-placeholder"
    fake_ai(monkeypatch, [])
    monkeypatch.setattr(type(service), "_enrich", lambda *a: (_ for _ in ()).throw(RuntimeError("panne")))
    with pytest.raises(RuntimeError):
        scan_project(service, tmp_path)
    assert service.storage.ai_tokens_since(MONTH, "org-1") > 0  # revue logique faite avant la panne


def test_training_ai_reviews_are_limited_per_day(api, service, monkeypatch):
    service.settings.openrouter_api_key = "sk-or-placeholder"
    service.settings.secuscan_training_ai_per_day = 2
    calls: list = []
    fake_ai(monkeypatch, calls)
    client = register(api(), "jane.doe@example.com")
    solution = EXERCISES_BY_ID["py-sqli"].solution
    results = [client.post("/api/training/exercises/py-sqli/submit", json={"code": solution}).json()
               for _ in range(3)]
    assert [r["ai"] is not None for r in results] == [True, True, False]
    assert all(r["passed"] for r in results)  # au-delà : correction automatique seule
    assert len(calls) == 2


def test_registrations_are_limited_per_ip(api):
    for i in range(5):
        register(api(), f"user{i}@example.com", org_name=f"Acme {i}")
    resp = api().post("/api/auth/register", json={"name": "x", "email": "late@example.com",
                                                  "password": PASSWORD, "org_name": "Acme"})
    assert resp.status_code == 429
