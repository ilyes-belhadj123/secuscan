from secuscan.ai import enricher as enricher_mod
from secuscan.ai.enricher import Enricher, _extract_json, unified_diff
from secuscan.ai.safety import REDACTED, sanitize
from secuscan.models import Scan
from secuscan.pipeline import new_id


def test_extract_json_with_fences():
    assert _extract_json('```json\n{"verdict": "uncertain"}\n```') == {"verdict": "uncertain"}


def test_sanitize_removes_payloads():
    text, filtered = sanitize("Un attaquant saisit ' OR '1'='1 pour contourner le filtre.")
    assert filtered and REDACTED in text
    text, filtered = sanitize("L'attaquant injecte du SQL pour lire toute la table.")
    assert not filtered


def test_unified_diff_uses_file_line_numbers():
    diff = unified_diff("a\nb\nc", "a\nB\nc", "x.py", start_line=40)
    assert "@@ -40,3 +40,3 @@" in diff
    assert "-b" in diff and "+B" in diff


def _fake_complete(self, prompt: str) -> dict:
    """Simule Claude : écarte la requête construite avec une constante, confirme le reste."""
    if prompt.startswith("Revue de logique"):
        if "backend-python/app.py" not in prompt:
            return {"findings": []}
        lines = prompt.split("\n")
        target = next(int(line.split("|")[0]) for line in lines if 'FROM invoices WHERE id = ?' in line)
        return {"findings": [
            {"title": "Accès à la facture d'un autre client (IDOR)", "cwe": "CWE-639", "severity": "high",
             "start_line": target, "end_line": target + 1, "confidence": 0.9,
             "message": "La facture est renvoyée sans vérifier qu'elle appartient à l'utilisateur connecté."},
            {"title": "Hypothèse peu sûre", "cwe": "CWE-000", "severity": "low",
             "start_line": 1, "end_line": 1, "confidence": 0.3, "message": "Spéculatif."},
        ]}
    if "Dépendance vulnérable" in prompt:
        return {"definition": "Version obsolète.", "attack_scenario": "Conceptuel.", "business_impact": "Fuite.",
                "difficulty": "facile", "fix_explanation": "Mettre à jour.", "best_practices": ["Renovate"]}
    excerpt = prompt.split("numérotées pour référence) :\n```\n")[1].split("\n```")[0]
    code = "\n".join(line.split(" | ", 1)[1] if " | " in line else "" for line in excerpt.split("\n"))
    if '"SELECT COUNT(*) FROM " + table' in code:
        return {"verdict": "false_positive", "confidence": 0.93, "reason": "Constante interne.",
                "patched_code": code}
    return {"verdict": "true_positive", "confidence": 0.9, "reason": "Entrée utilisateur.",
            "definition": "Faille.", "attack_scenario": "Un attaquant saisit ' OR '1'='1 dans le champ.",
            "business_impact": "Fuite de données.", "difficulty": "facile",
            "patched_code": code.replace("execute(f\"", "execute(\"") + "\n# corrigé",
            "fix_explanation": "Requête paramétrée.", "best_practices": ["Valider les entrées"]}


def test_pipeline_with_ai(monkeypatch, service):
    from secuscan.config import DEMO_PROJECT_DIR

    monkeypatch.setattr(Enricher, "_complete", _fake_complete)
    scan = Scan(id=new_id(), project_name="Acme Shop (démo)", source="demo")
    service.storage.save_scan(scan)
    findings = service.run(scan, DEMO_PROJECT_DIR)

    fps = [f for f in findings if f.status == "false_positive"]
    assert len(fps) == 1 and fps[0].start_line == 42
    assert scan.summary.false_positives == 1

    sqli = next(f for f in findings if f.rule_id == "PY-SQLI" and f.start_line == 30)
    assert sqli.ai and sqli.ai.fix and sqli.ai.fix.diff.startswith("--- a/backend-python/app.py")
    assert sqli.ai.fix.syntax_valid is True
    assert sqli.ai.filtered and "OR '1'" not in sqli.ai.explanation.attack_scenario

    # Les secrets ne sont jamais écartés par l'IA, et restent masqués dans ce qui lui est envoyé
    assert all(f.status == "open" for f in findings if f.kind == "secret")

    # Revue logique : l'IDOR est ajouté (et validé comme les autres), le résultat à faible confiance est ignoré
    logic = [f for f in findings if f.kind == "ai"]
    assert len(logic) == 1
    idor = logic[0]
    assert idor.cwe == "CWE-639" and idor.owasp and idor.owasp.startswith("A01")
    assert "def get_invoice" in idor.snippet and idor.ai and idor.ai.verdict == "true_positive"
    assert scan.summary.by_kind["ai"] == 1


def test_prompt_never_contains_secret(monkeypatch, service, tmp_path):
    sent: list[str] = []
    monkeypatch.setattr(Enricher, "_complete", lambda self, prompt: sent.append(prompt) or {"verdict": "uncertain"})
    project = tmp_path / "p"
    project.mkdir()
    (project / "app.py").write_text('API_KEY = "Zx9-UnitTest-Secret-Value"\nimport os\nos.system(cmd)\n')
    scan = Scan(id=new_id(), project_name="Acme", source="upload")
    service.storage.save_scan(scan)
    service.run(scan, project)
    assert sent and not any("Zx9-UnitTest-Secret-Value" in p for p in sent)


def test_ai_unavailable_is_graceful(service, tmp_path):
    assert not enricher_mod.Enricher(service.settings, service.storage).settings.ai_enabled
    project = tmp_path / "p"
    project.mkdir()
    (project / "app.py").write_text("import os\nos.system(cmd)\n")
    scan = Scan(id=new_id(), project_name="Acme", source="upload")
    service.storage.save_scan(scan)
    findings = service.run(scan, project)
    assert scan.status == "completed"
    assert findings[0].ai is None and findings[0].ai_error
