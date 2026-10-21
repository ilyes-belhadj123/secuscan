"""Garde-fou de non-régression du moteur de règles sur le benchmark (SS-8)."""
from secuscan.benchmark import load_expected, run, same_family
from secuscan.config import REPO_ROOT

TRUTH = REPO_ROOT / "benchmark" / "ground_truth.json"


def test_ground_truth_anchors_are_unique():
    sources = load_expected(TRUTH)
    assert sum(len(items) for _, items, _ in sources) >= 150


def test_external_truth_is_pinned_and_in_scope():
    import json
    import re

    from secuscan.benchmark import in_scope
    data = json.loads((REPO_ROOT / "benchmark" / "external.json").read_text(encoding="utf-8"))
    for src in data["sources"]:
        assert src["repo"].startswith("https://github.com/") and re.fullmatch(r"[0-9a-f]{40}", src["commit"])
        assert src["scope"] and all(in_scope(path, src["scope"]) for path in src["expected"])
        assert all(entry["cwe"].startswith("CWE-") for entries in src["expected"].values() for entry in entries)


def test_cwe_families():
    assert same_family("CWE-95", "CWE-1336")
    assert same_family("CWE-328", "CWE-916")
    assert not same_family("CWE-89", "CWE-79")


def test_rules_only_benchmark_thresholds():
    result = run(with_ai=False, truth=TRUTH)
    stats = result.stats()
    # Seuils juste sous la mesure actuelle (99 % / 2 %) : échoue dès qu'une modification fait perdre
    # quelques failles ou ajoute quelques faux positifs
    assert stats["recall"] >= 0.97
    assert stats["fp_rate"] <= 0.05
