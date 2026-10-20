"""SS-18 — logo de l'organisation dans le rapport PDF."""
import io

import pytest
from conftest import register
from PIL import Image

from secuscan.branding import LogoError, normalize_logo
from secuscan.models import Scan
from secuscan.pipeline import new_id
from secuscan.reports import build_pdf


def _image(fmt: str = "PNG", size=(1200, 300)) -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", size, (29, 78, 216)).save(buf, format=fmt)
    return buf.getvalue()


def test_normalize_reencodes_and_shrinks():
    png = normalize_logo(_image("JPEG"))
    with Image.open(io.BytesIO(png)) as img:
        assert img.format == "PNG" and img.size == (600, 150)


@pytest.mark.parametrize("data, message", [
    (b"<svg xmlns='http://www.w3.org/2000/svg'></svg>", "illisible"),
    (_image("GIF", (10, 10)), "PNG ou JPEG"),
    (b"\x89PNG" + b"0" * (1024 * 1024), "trop lourd"),
    (_image("PNG", (4100, 4000)), "trop grande"),
], ids=["svg", "gif", "trop-lourd", "trop-grande"])
def test_rejects_bad_files(data, message):
    with pytest.raises(LogoError, match=message):
        normalize_logo(data)


def test_logo_upload_and_pdf(api, service, tmp_path):
    client = register(api(), "jane.doe@example.com")  # première organisation : offre Business
    assert client.get("/api/org/logo").status_code == 404
    resp = client.put("/api/org/logo", files={"file": ("logo.png", _image(), "image/png")})
    assert resp.status_code == 200, resp.text
    logo = client.get("/api/org/logo")
    assert logo.status_code == 200 and logo.headers["content-type"] == "image/png"
    assert client.get("/api/audit").json()[0]["action"] == "org.logo_updated"

    project = tmp_path / "p"
    project.mkdir()
    (project / "app.py").write_text("import os\nos.system(cmd)\n")
    org_id = client.get("/api/auth/me").json()["org"]["id"]
    scan = Scan(id=new_id(), project_name="Acme", source="upload", org_id=org_id)
    service.storage.save_scan(scan)
    service.run(scan, project)
    with_logo = client.get(f"/api/scans/{scan.id}/report.pdf")
    assert with_logo.status_code == 200 and b"/Subtype /Image" in with_logo.content

    assert client.delete("/api/org/logo").status_code == 200
    assert b"/Subtype /Image" not in client.get(f"/api/scans/{scan.id}/report.pdf").content


def test_logo_reserved_to_business_admins(api):
    owner = register(api(), "jane.doe@example.com")
    resp = owner.post("/api/org/invitations", json={"email": "john.doe@example.com", "role": "member"})
    member = register(api(), "john.doe@example.com", org_name=None, invitation_token=resp.json()["url"].rsplit("/", 1)[1])
    free_owner = register(api(), "bob@example.com", org_name="Globex")  # organisation suivante : offre Free
    files = {"file": ("logo.png", _image(), "image/png")}
    assert member.put("/api/org/logo", files=files).status_code == 403
    assert free_owner.put("/api/org/logo", files=files).status_code == 402


def test_pdf_logo_keeps_ratio():
    scan = Scan(id=new_id(), project_name="Acme", source="upload", status="completed", completed_at="2026-10-16T10:00:00")
    pdf = build_pdf(scan, [], logo=normalize_logo(_image(size=(100, 400))))
    assert pdf.startswith(b"%PDF") and b"/Subtype /Image" in pdf
