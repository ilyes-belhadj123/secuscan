"""SS-12 — budget IA par analyse, priorisation et coûts."""
import pytest

from secuscan.ai.enricher import AIBudget, AIStats, BudgetExceeded, Enricher
from secuscan.config import DEMO_PROJECT_DIR, Settings
from secuscan.models import Scan
from secuscan.pipeline import ScanService, new_id
from secuscan.storage import Storage


def test_budget_blocks_after_max_calls():
    budget = AIBudget(max_calls=2, max_tokens=10_000)
    budget.reserve()
    budget.reserve()
    with pytest.raises(BudgetExceeded):
        budget.reserve()
    assert budget.refused == 1


def test_budget_blocks_after_max_tokens():
    budget = AIBudget(max_calls=100, max_tokens=1_000)
    budget.reserve()
    budget.consume(1_500)
    with pytest.raises(BudgetExceeded):
        budget.reserve()


def test_cost_estimate():
    settings = Settings(_env_file=None, secuscan_ai_price_input_per_mtok=2.0, secuscan_ai_price_output_per_mtok=10.0)
    stats = AIStats()
    stats.add(call=True, prompt_tokens=1_000_000, completion_tokens=100_000)
    assert stats.cost_usd(settings) == pytest.approx(3.0)


def _fake_complete(self, prompt):
    self.budget.reserve()  # comme un vrai appel non mis en cache
    self.stats.add(call=True, prompt_tokens=1000, completion_tokens=200)
    if prompt.startswith("Revue de logique"):
        return {"findings": []}
    if "Dépendance vulnérable" in prompt:
        return {"definition": "d", "attack_scenario": "a", "business_impact": "b", "difficulty": "facile",
                "fix_explanation": "f", "best_practices": []}
    return {"verdict": "true_positive", "confidence": 0.9, "reason": "r", "definition": "d",
            "attack_scenario": "a", "business_impact": "b", "difficulty": "facile", "patched_code": ""}


def test_small_budget_prioritises_critical_findings(monkeypatch, tmp_path):
    settings = Settings(
        _env_file=None, openrouter_api_key="test-key-placeholder", secuscan_data_dir=tmp_path,
        secuscan_offline=True, secuscan_plan="free", secuscan_ai_concurrency=1,
    )
    monkeypatch.setattr("secuscan.config.PLAN_AI_BUDGETS", {"free": (12, 1_000_000), "pro": (150, 500_000)})
    monkeypatch.setattr(Enricher, "_complete", _fake_complete)
    service = ScanService(settings, Storage(tmp_path / "b.db"))
    scan = Scan(id=new_id(), project_name="Acme budget", source="demo")
    service.storage.save_scan(scan)
    findings = service.run(scan, DEMO_PROJECT_DIR)

    s = scan.summary
    assert s.ai_calls <= 12 and s.ai_budget_refused > 0
    assert any("Budget IA atteint" in w for w in s.warnings)
    # Les alertes critiques sont traitées en priorité : aucune critique de code privée d'IA avant une faible
    enriched = [f for f in findings if f.kind != "dependency" and f.ai]
    skipped = [f for f in findings if f.kind != "dependency" and f.ai is None and f.status == "open"]
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    assert enriched and skipped
    assert max(order[f.severity] for f in enriched) <= min(order[f.severity] for f in skipped)
    assert s.ai_cost_usd > 0 and s.plan == "free"
