"""SS-21 — bêta : retours sur les correctifs, taux d'acceptation, questionnaire, tableau de bord opérateur."""
from datetime import UTC, datetime, timedelta

import pytest
from conftest import register

from secuscan.beta import nps
from secuscan.models import Scan
from secuscan.pipeline import new_id


@pytest.fixture
def org(api, service, tmp_path):
    client = register(api(), "jane.doe@example.com")
    org_id = client.get("/api/auth/me").json()["org"]["id"]
    project = tmp_path / "p"
    project.mkdir()
    (project / "app.py").write_text("import os\nos.system(cmd)\neval(expr)\nexec(code)\n", encoding="utf-8")
    scan = Scan(id=new_id(), project_name="Acme API", source="upload", org_id=org_id)
    service.storage.save_scan(scan)
    findings = service.run(scan, project)
    return client, [f.id for f in findings], org_id


def test_acceptance_rate(org):
    client, ids, _ = org
    for fid, verdict in zip(ids, ["applied", "helpful", "not_helpful"], strict=False):
        assert client.post(f"/api/findings/{fid}/feedback", json={"verdict": verdict}).status_code == 200
    client.post(f"/api/findings/{ids[0]}/feedback", json={"verdict": "applied", "comment": "Correctif repris tel quel"})
    client.post(f"/api/findings/{ids[0]}/fix-copied")
    client.post(f"/api/findings/{ids[0]}/fix-copied")  # une copie par personne et par alerte
    m = client.get("/api/beta/metrics").json()
    assert m["feedback"] == {"applied": 1, "helpful": 1, "not_helpful": 1}
    assert m["acceptance_rate"] == pytest.approx(0.667, abs=0.001) and m["fix_copies"] == 1
    assert client.get(f"/api/findings/{ids[0]}/feedback").json()["comment"] == "Correctif repris tel quel"


def test_feedback_scoped_to_org(api, org):
    _, ids, _ = org
    other = register(api(), "bob@example.com", org_name="Globex")
    assert other.post(f"/api/findings/{ids[0]}/feedback", json={"verdict": "applied"}).status_code == 404
    assert other.post(f"/api/findings/{ids[0]}/fix-copied").status_code == 404
    assert other.get("/api/beta/metrics").json()["feedback_total"] == 0


def test_returned_next_week(org, service):
    client, _, org_id = org
    assert client.get("/api/beta/metrics").json()["returned"] is False
    later = Scan(id=new_id(), project_name="Acme API", source="upload", org_id=org_id, status="completed",
                 created_at=(datetime.now(UTC) + timedelta(days=8)).isoformat())
    service.storage.save_scan(later)
    m = client.get("/api/beta/metrics").json()
    assert m["returned"] is True and m["active_weeks"] == 2


def test_survey_due_after_14_days(org, service):
    client, _, org_id = org
    assert client.get("/api/beta/survey").json()["due"] is False  # organisation créée à l'instant
    old = (datetime.now(UTC) - timedelta(days=15)).isoformat()
    with service.storage._conn() as conn:
        conn.execute("UPDATE organizations SET created_at = ? WHERE id = ?", (old, org_id))
    assert client.get("/api/beta/survey").json()["due"] is True
    assert client.post("/api/beta/survey", json={"recommend": 11}).status_code == 422
    assert client.post("/api/beta/survey", json={"recommend": 9, "useful": "Les correctifs",
                                                 "missing": "Intégration Jira"}).status_code == 200
    assert client.get("/api/beta/survey").json() == {"due": False, "answered": True}


def test_operator_dashboard_access(api, org, service):
    client, ids, _ = org
    assert client.get("/api/operator/beta").status_code == 403  # propriétaire d'une org ≠ opérateur
    service.settings.secuscan_operator_emails = ["jane.doe@example.com"]
    client.post(f"/api/findings/{ids[0]}/feedback", json={"verdict": "applied", "comment": "Très clair"})
    client.post("/api/beta/survey", json={"recommend": 10})
    register(api(), "bob@example.com", org_name="Globex")
    data = client.get("/api/operator/beta").json()
    assert data["totals"]["organizations"] == 2 and data["totals"]["active"] == 1
    assert data["totals"]["acceptance_rate"] == 1.0 and data["totals"]["nps"] == 100
    assert data["comments"] == [{"verdict": "applied", "rule_id": "PY-CMDI", "comment": "Très clair"}]
    # Aucun code ni contenu d'alerte dans le tableau de bord opérateur
    assert "os.system" not in str(data)


def test_nps():
    assert nps([10, 9, 8, 7, 3]) == 20
    assert nps([]) is None
