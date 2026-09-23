"""SS-10 — contrôle qualité des explications IA : échantillon + vérifications automatiques.

Usage (dans apps/api) :  uv run python -m secuscan.qa_explanations [--size 30]
Produit docs/qa/explications-echantillon.md, support de la relecture humaine.
"""
import argparse
import re
import sys
from collections import defaultdict

from .ai.safety import _OFFENSIVE
from .config import REPO_ROOT, get_settings
from .models import Finding
from .storage import Storage

_FRENCH = re.compile(r"\b(le|la|les|des|une|est|pour|dans|qui|pas|avec|sur|être|peut)\b", re.I)
_ENGLISH = re.compile(r"\b(the|this|which|attacker|could|should|would|with the|data is)\b", re.I)


def checks(f: Finding) -> dict[str, bool]:
    e = f.ai.explanation
    text = " ".join([e.definition, e.attack_scenario, e.business_impact])
    return {
        "complète": all([e.definition, e.attack_scenario, e.business_impact, e.difficulty]),
        "français": len(_FRENCH.findall(text)) >= 8 and len(_ENGLISH.findall(text)) <= 1,
        "sans charge offensive": not any(p.search(text) for p in _OFFENSIVE) and not f.ai.filtered,
        "références": any("cwe.mitre.org" in r or "owasp.org" in r or "osv.dev" in r for r in e.references),
        "longueur": 150 <= len(text) <= 2500,
        "correctif": f.kind == "dependency" or bool(f.ai.fix and f.ai.fix.syntax_valid is not False),
    }


def sample(storage: Storage, size: int) -> list[Finding]:
    """Échantillon diversifié : une explication par (CWE, langage) en priorité, alertes ouvertes, IA réelle."""
    pool = []
    for scan in storage.list_scans():
        if scan.status == "completed" and not scan.project_name.startswith("benchmark:"):
            pool += [f for f in storage.list_findings(scan.id)
                     if f.status == "open" and f.ai and f.ai.generated_by == "ai" and f.ai.explanation]
    seen: set[tuple] = set()
    by_group: dict[tuple, list[Finding]] = defaultdict(list)
    for f in pool:
        key = (f.fingerprint, f.rule_id)
        if key not in seen:
            seen.add(key)
            by_group[(f.cwe, f.language)].append(f)
    picked: list[Finding] = []
    while len(picked) < size and any(by_group.values()):
        for group in sorted(by_group, key=str):
            if by_group[group] and len(picked) < size:
                picked.append(by_group[group].pop(0))
    return picked


def main() -> int:
    parser = argparse.ArgumentParser(description="Échantillon de relecture des explications IA (SS-10)")
    parser.add_argument("--size", type=int, default=30)
    args = parser.parse_args()

    storage = Storage(get_settings().data_dir / "secuscan.db")
    items = sample(storage, args.size)
    results = [(f, checks(f)) for f in items]
    names = list(results[0][1]) if results else []
    out = ["# Relecture des explications IA (SS-10)", "",
           f"Échantillon : {len(items)} explications générées par le modèle, diversifiées par CWE et langage.", "",
           "## Contrôles automatiques", "", "| Contrôle | Réussis |", "|---|---|"]
    for name in names:
        ok = sum(1 for _, c in results if c[name])
        out.append(f"| {name} | {ok}/{len(results)} |")
    out += ["", "## Échantillon", ""]
    for i, (f, c) in enumerate(results, start=1):
        e = f.ai.explanation
        failed = [k for k, v in c.items() if not v]
        out += [
            f"### {i}. {f.title} — `{f.file}:{f.start_line}`",
            f"{f.language} · {f.cwe} · {f.severity.value} · verdict {f.ai.verdict} ({f.ai.confidence:.0%})"
            + (f" · ⚠ contrôles échoués : {', '.join(failed)}" if failed else " · ✓ contrôles automatiques"),
            "", f"- **Le problème** : {e.definition}", f"- **Attaque** : {e.attack_scenario}",
            f"- **Impact** : {e.business_impact}", f"- **Difficulté** : {e.difficulty}",
            f"- **Correctif** : {f.ai.fix.explanation if f.ai.fix else '—'}", "",
        ]
    target = REPO_ROOT / "docs" / "qa" / "explications-echantillon.md"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("\n".join(out) + "\n", encoding="utf-8")
    print(f"{len(items)} explications exportées dans {target}")
    for name in names:
        print(f"  {name:24} {sum(1 for _, c in results if c[name])}/{len(results)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
