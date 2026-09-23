"""Tests de l'API HTTP (IA désactivée, OSV hors ligne)."""
import pytest
from conftest import register

from secuscan.models import Scan
from secuscan.pipeline import new_id


@pytest.fixture
def client(api, service, tmp_path):
    http = register(api(), "jane.doe@example.com")
    org_id = http.get("/api/auth/me").json()["org"]["id"]
    project = tmp_path / "proj"
    project.mkdir()
    (project / "app.py").write_text("import os\nos.system(cmd)\nexec(user_code)\n", encoding="utf-8")
    scan = Scan(id=new_id(), project_name="Acme API", source="upload", org_id=org_id)
    service.storage.save_scan(scan)
    service.run(scan, project)
    return http, scan.id


def test_dismiss_updates_summary_and_audit(client):
    http, scan_id = client
    before = http.get(f"/api/scans/{scan_id}").json()
    assert before["summary"]["total"] == 2
    finding = http.get(f"/api/scans/{scan_id}/findings").json()[0]

    resp = http.post(f"/api/findings/{finding['id']}/dismiss", json={"reason": "accepted_risk", "justification": "trop"})
    assert resp.status_code == 422  # justification obligatoire (10 caractères min.)

    resp = http.post(f"/api/findings/{finding['id']}/dismiss",
                     json={"reason": "accepted_risk", "justification": "Commande interne sans entrée utilisateur."})
    assert resp.status_code == 200
    after = http.get(f"/api/scans/{scan_id}").json()
    assert after["summary"]["total"] == 1 and after["summary"]["dismissed"] == 1
    assert after["score"] > before["score"]

    entries = http.get("/api/audit").json()
    assert any(e["action"] == "finding.dismissed" and e["actor"] == "jane.doe@example.com" for e in entries)


def test_pdf_white_label(client):
    http, scan_id = client
    params = {"prepared_for": "Acme Corp", "prepared_by": "Exemple Conseil"}
    resp = http.get(f"/api/scans/{scan_id}/report.pdf", params=params)
    assert resp.status_code == 200 and resp.content.startswith(b"%PDF")
    export = http.get("/api/audit").json()[0]
    assert export["action"] == "report.exported" and export["details"]["prepared_by"] == "Exemple Conseil"


def test_git_endpoint_rejects_bad_url(client):
    http, _ = client
    resp = http.post("/api/scans/git", json={"url": "https://evil.example.com/acme/shop"})
    assert resp.status_code == 400
