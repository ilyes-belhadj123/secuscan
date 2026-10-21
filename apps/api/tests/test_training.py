"""SS-24 — mode formation : exercices, correction automatique, progression."""
import pytest
from conftest import register

from secuscan.ai.enricher import Enricher
from secuscan.training import grade
from secuscan.training_exercises import EXERCISES, EXERCISES_BY_ID


def test_catalog_covers_languages_and_infrastructure():
    assert len(EXERCISES) == 18 and len(EXERCISES_BY_ID) == 18
    assert {e.language for e in EXERCISES} == {"python", "javascript", "php", "java", "csharp", "go",
                                                "dockerfile", "kubernetes"}


@pytest.mark.parametrize("ex", EXERCISES, ids=lambda e: e.id)
def test_original_fails_and_solution_passes(ex):
    original = {c.label: c.ok for c in grade(ex, ex.code)}
    assert original["La faille n'est plus détectée"] is False
    assert all(c.ok for c in grade(ex, ex.solution)), [c for c in grade(ex, ex.solution) if not c.ok]


def test_cheating_is_rejected():
    ex = EXERCISES_BY_ID["py-sqli"]
    silenced = ex.code.replace("    cursor.execute(", "    # secuscan: ignore[PY-SQLI]\n    cursor.execute(")
    assert not all(c.ok for c in grade(ex, silenced))
    emptied = "def find_customer(conn, email):\n    return None\n"  # faille « corrigée » en supprimant tout
    failed = [c.label for c in grade(ex, emptied) if not c.ok]
    assert "La requête utilise un paramètre « ? » passé séparément" in failed
    broken = ex.solution.replace("(email,))", "(email,)")
    assert [c for c in grade(ex, broken) if c.label == "Syntaxe valide"][0].ok is False


def test_submission_flow_and_progress(api):
    client = register(api(), "jane.doe@example.com")
    listing = client.get("/api/training/exercises").json()
    assert listing["total"] == len(EXERCISES) and listing["passed"] == 0

    ex = EXERCISES_BY_ID["js-xss"]
    detail = client.get("/api/training/exercises/js-xss").json()
    assert detail["code"] == ex.code and detail["solution"] is None  # solution cachée avant réussite

    failed = client.post("/api/training/exercises/js-xss/submit", json={"code": ex.code}).json()
    assert failed["passed"] is False and failed["solution"] is None
    assert any(not c["ok"] and c["label"] == "La faille n'est plus détectée" for c in failed["checks"])

    ok = client.post("/api/training/exercises/js-xss/submit", json={"code": ex.solution}).json()
    assert ok["passed"] is True and ok["solution"] == ex.solution and ok["ai"] is None  # IA non configurée

    detail = client.get("/api/training/exercises/js-xss").json()
    assert detail["passed"] and detail["attempts"] == 2 and detail["last_code"] == ex.solution
    assert client.get("/api/training/exercises").json()["passed"] == 1
    assert client.get("/api/training/exercises/inconnu").status_code == 404


def test_team_progress_for_admins_only(api):
    owner = register(api(), "jane.doe@example.com")
    resp = owner.post("/api/org/invitations", json={"email": "john.doe@example.com", "role": "member"})
    member = register(api(), "john.doe@example.com", org_name=None, invitation_token=resp.json()["url"].rsplit("/", 1)[1])
    member.post("/api/training/exercises/py-yaml/submit", json={"code": EXERCISES_BY_ID["py-yaml"].solution})
    assert member.get("/api/training/progress").status_code == 403
    rows = {m["email"]: m for m in owner.get("/api/training/progress").json()["members"]}
    assert rows["john.doe@example.com"]["passed"] == 1 and rows["jane.doe@example.com"]["passed"] == 0
    # Une autre organisation ne voit pas cette progression
    other = register(api(), "bob@example.com", org_name="Globex")
    assert [m["email"] for m in other.get("/api/training/progress").json()["members"]] == ["bob@example.com"]


@pytest.mark.parametrize("fixed, expected", [(True, True), (False, False)])
def test_ai_review_confirms_or_rejects(api, service, monkeypatch, fixed, expected):
    service.settings.openrouter_api_key = "placeholder-key"
    monkeypatch.setattr(Enricher, "_complete", lambda self, prompt, **kw: {
        "fixed": fixed, "feedback": "Bien vu : textContent n'interprète pas le HTML."})
    client = register(api(), "jane.doe@example.com")
    result = client.post("/api/training/exercises/js-xss/submit",
                         json={"code": EXERCISES_BY_ID["js-xss"].solution}).json()
    assert result["passed"] is expected and result["ai"]["feedback"].startswith("Bien vu")


def test_broken_yaml_is_rejected():
    ex = EXERCISES_BY_ID["k8s-hardening"]
    broken = ex.solution.replace("  replicas: 2", "  replicas: [2")
    syntax = next(c for c in grade(ex, broken) if c.label == "Syntaxe valide")
    assert not syntax.ok and "ligne" in syntax.detail
