"""Revue logique IA : tous les fichiers de code relus, les grands par tranches, dans le budget de l'offre."""
from secuscan.ai.enricher import AIBudget, LogicFlaw
from secuscan.ingest import SourceFile
from secuscan.models import Scan, Severity
from secuscan.pipeline import new_id


class FakeEnricher:
    def __init__(self, max_calls: int, flaw_at: int | None = None):
        self.budget = AIBudget(max_calls, 10_000_000)
        self.calls: list[tuple[str, int, int]] = []
        self.flaw_at = flaw_at

    def discover_logic_flaws(self, source, flagged, first=1, last=None):
        self.calls.append((source.path, first, last))
        if self.flaw_at and first <= self.flaw_at <= last:  # vue par les deux tranches qui se chevauchent
            return [LogicFlaw("Contrôle d'accès absent", "CWE-639", Severity.high, self.flaw_at, self.flaw_at, 0.9, "")]
        return []


def code(lines: int) -> str:
    return "\n".join(f"x{i} = {i}" for i in range(lines))


def files(count: int, lines: int = 10) -> dict:
    return {f"src/m{i}.py": SourceFile(f"src/m{i}.py", "python", code(lines)) for i in range(count)}


def run(service, redacted, enricher, findings=None):
    service.settings.openrouter_api_key = "sk-or-placeholder"  # IA « configurée », jamais appelée ici
    scan = Scan(id=new_id(), project_name="Acme", source="upload")
    service.storage.save_scan(scan)
    return scan, service._logic(scan, findings or [], redacted, enricher)


def test_every_file_is_reviewed_beyond_forty(service):
    enricher = FakeEnricher(max_calls=500)
    scan, _ = run(service, files(87), enricher)
    assert len({path for path, _, _ in enricher.calls}) == 87
    assert not any("non relus" in w for w in scan.summary.warnings)


def test_large_file_is_reviewed_in_overlapping_slices_without_duplicates(service):
    service.settings.secuscan_logic_max_lines = 400
    enricher = FakeEnricher(max_calls=500, flaw_at=385)  # dans la zone commune des tranches 1 et 2
    redacted = {"big.py": SourceFile("big.py", "python", code(1000))}
    _, flaws = run(service, redacted, enricher)
    assert sorted(enricher.calls) == [("big.py", 1, 400), ("big.py", 371, 770), ("big.py", 741, 1000)]
    assert [f.start_line for f in flaws] == [385]


def test_plan_budget_still_applies_and_is_explained(service):
    enricher = FakeEnricher(max_calls=12)
    scan, _ = run(service, files(30), enricher)
    assert len(enricher.calls) == 12
    assert any("Budget IA de l'offre" in w and "18 fichier(s) non relus" in w for w in scan.summary.warnings)
