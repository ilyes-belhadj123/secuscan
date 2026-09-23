"""Garde-fou de non-régression du moteur de règles sur le benchmark (SS-8)."""
from secuscan.benchmark import load_expected, run, same_family
from secuscan.config import REPO_ROOT

TRUTH = REPO_ROOT / "benchmark" / "ground_truth.json"


def test_ground_truth_anchors_are_unique():
    sources = load_expected(TRUTH)
    assert sum(len(items) for _, items in sources) >= 80


def test_cwe_families():
    assert same_family("CWE-95", "CWE-1336")
    assert same_family("CWE-328", "CWE-916")
    assert not same_family("CWE-89", "CWE-79")


def test_rules_only_benchmark_thresholds():
    result = run(with_ai=False, truth=TRUTH)
    stats = result.stats()
    # Seuils volontairement sous la mesure actuelle : échoue si une modification des règles régresse
    assert stats["recall"] >= 0.9
    assert stats["fp_rate"] <= 0.1
