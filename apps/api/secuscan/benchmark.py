"""SS-8 — benchmark de détection : taux de détection (rappel) et taux de faux positifs.

Usage (dans apps/api) :
    uv run python -m secuscan.benchmark                 # règles seules, hors ligne (CI)
    uv run python -m secuscan.benchmark --ai            # règles + IA (clé OpenRouter requise)
    uv run python -m secuscan.benchmark --min-recall 0.6

Le corpus et sa vérité terrain sont dans benchmark/ (racine du dépôt). Les dépendances (SCA)
sont exclues : leur détection dépend de la base OSV, pas du moteur d'analyse.
"""
import argparse
import json
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from .config import REPO_ROOT, Settings, get_settings
from .ingest import LANGUAGE_BY_EXTENSION
from .models import Finding, Scan
from .pipeline import ScanService, new_id
from .storage import Storage

BENCHMARK_DIR = REPO_ROOT / "benchmark"
LINE_TOLERANCE = 2

# CWE considérés comme équivalents pour l'appariement (même famille de faille)
_CWE_GROUPS = [
    {"CWE-94", "CWE-95", "CWE-1336"},
    {"CWE-327", "CWE-328", "CWE-916"},
    {"CWE-330", "CWE-338"},
    {"CWE-489", "CWE-215"},
    {"CWE-98", "CWE-22"},
    {"CWE-639", "CWE-284", "CWE-285", "CWE-862", "CWE-863"},
    {"CWE-602", "CWE-472", "CWE-840", "CWE-841"},
]


def same_family(a: str | None, b: str | None) -> bool:
    if not a or not b:
        return False
    return a == b or any(a in g and b in g for g in _CWE_GROUPS)


@dataclass
class Expected:
    source: str
    file: str
    line: int
    cwe: str
    anchor: str
    matched_by: Finding | None = None

    @property
    def language(self) -> str:
        return LANGUAGE_BY_EXTENSION.get(Path(self.file).suffix, "?")


@dataclass
class Result:
    mode: str
    expected: list[Expected] = field(default_factory=list)
    false_positives: list[Finding] = field(default_factory=list)
    duplicates: int = 0
    rejected_by_ai: int = 0

    def stats(self, language: str | None = None) -> dict:
        exp = [e for e in self.expected if language is None or e.language == language]
        fps = [f for f in self.false_positives if language is None or f.language == language]
        tp = sum(1 for e in exp if e.matched_by)
        fn = len(exp) - tp
        fp = len(fps)
        return {
            "tp": tp, "fn": fn, "fp": fp,
            "recall": tp / len(exp) if exp else None,
            "fp_rate": fp / (tp + fp) if tp + fp else None,
        }


def load_expected(path: Path) -> list[tuple[Path, list[Expected]]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    sources = []
    for src in data["sources"]:
        root = REPO_ROOT / src["path"]
        items = []
        for rel, entries in src["expected"].items():
            lines = (root / rel).read_text(encoding="utf-8").split("\n")
            for entry in entries:
                hits = [i for i, line in enumerate(lines, start=1) if entry["contains"] in line]
                if len(hits) != 1:
                    raise ValueError(f"{src['name']}/{rel} : ancre « {entry['contains']} » trouvée {len(hits)} fois")
                items.append(Expected(src["name"], rel, hits[0], entry["cwe"], entry["contains"]))
        sources.append((root, items))
    return sources


def match(expected: list[Expected], findings: list[Finding], result: Result) -> None:
    code_findings = [f for f in findings if f.kind != "dependency"]
    result.rejected_by_ai += sum(1 for f in code_findings if f.status == "false_positive")
    for f in (f for f in code_findings if f.status == "open"):
        candidates = [
            e for e in expected
            if e.file == f.file and same_family(e.cwe, f.cwe)
            and f.start_line - LINE_TOLERANCE <= e.line <= f.end_line + LINE_TOLERANCE
        ]
        free = [e for e in candidates if e.matched_by is None]
        if free:
            free[0].matched_by = f
        elif candidates:
            result.duplicates += 1  # même faille signalée deux fois : ni vrai ni faux positif
        else:
            result.false_positives.append(f)


def run(with_ai: bool, truth: Path) -> Result:
    base = get_settings()
    result = Result(mode="règles + IA" if with_ai else "règles seules")
    with tempfile.TemporaryDirectory(prefix="secuscan-bench-") as tmp:
        settings = Settings(
            _env_file=None if not with_ai else base.model_config.get("env_file"),
            openrouter_api_key=base.openrouter_api_key if with_ai else "",
            openrouter_model=base.openrouter_model,
            secuscan_data_dir=Path(tmp), secuscan_offline=True,
        )
        if with_ai and not settings.ai_enabled:
            raise SystemExit("--ai demande OPENROUTER_API_KEY (fichier .env).")
        # Le cache IA de la démo est réutilisé pour éviter de repayer les mêmes appels
        storage = Storage(base.data_dir / "secuscan.db") if with_ai else Storage(Path(tmp) / "bench.db")
        service = ScanService(settings, storage)
        for root, expected in load_expected(truth):
            scan = Scan(id=new_id(), project_name=f"benchmark:{root.name}", source="upload")
            storage.save_scan(scan)
            match(expected, service.run(scan, root), result)
            result.expected += expected
    return result


def _pct(value: float | None) -> str:
    return "—" if value is None else f"{value * 100:.0f} %"


def to_markdown(result: Result) -> str:
    languages = sorted({e.language for e in result.expected})
    total = result.stats()
    out = [
        f"# Benchmark SecuScan — {result.mode}",
        "",
        f"Exécuté le {datetime.now(UTC).strftime('%d/%m/%Y %H:%M')} UTC · "
        f"{len(result.expected)} failles attendues · tolérance ±{LINE_TOLERANCE} lignes",
        "",
        "| Langage | Détectées | Manquées | Faux positifs | Taux de détection | Taux de faux positifs |",
        "|---|---|---|---|---|---|",
    ]
    for lang in languages:
        s = result.stats(lang)
        out.append(f"| {lang} | {s['tp']} | {s['fn']} | {s['fp']} | {_pct(s['recall'])} | {_pct(s['fp_rate'])} |")
    out.append(f"| **Total** | **{total['tp']}** | **{total['fn']}** | **{total['fp']}** | "
               f"**{_pct(total['recall'])}** | **{_pct(total['fp_rate'])}** |")
    out += ["", f"Alertes écartées par la validation IA : {result.rejected_by_ai} · doublons : {result.duplicates}", ""]
    out += ["## Failles manquées", ""]
    missed = [e for e in result.expected if not e.matched_by]
    out += [f"- `{e.source}/{e.file}:{e.line}` {e.cwe} — `{e.anchor}`" for e in missed] or ["Aucune."]
    out += ["", "## Faux positifs", ""]
    out += [f"- `{f.file}:{f.start_line}` {f.rule_id} ({f.cwe}) — {f.title}" for f in result.false_positives] or ["Aucun."]
    return "\n".join(out) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark de détection SecuScan (SS-8)")
    parser.add_argument("--ai", action="store_true", help="active la validation et la revue logique IA")
    parser.add_argument("--min-recall", type=float, default=0.0, help="échec si le taux de détection est inférieur")
    parser.add_argument("--truth", type=Path, default=BENCHMARK_DIR / "ground_truth.json")
    parser.add_argument("--output", type=Path, default=None, help="fichier Markdown du rapport")
    args = parser.parse_args()

    result = run(args.ai, args.truth)
    report = to_markdown(result)
    print(report)
    output = args.output or BENCHMARK_DIR / "results" / ("latest-ai.md" if args.ai else "latest-rules.md")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(report, encoding="utf-8")
    print(f"Rapport écrit dans {output}")

    recall = result.stats()["recall"] or 0.0
    if recall < args.min_recall:
        print(f"ÉCHEC : taux de détection {recall:.0%} < seuil {args.min_recall:.0%}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
