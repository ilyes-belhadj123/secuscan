import sqlite3

from secuscan.analyzers.sast import analyze_file
from secuscan.analyzers.secrets import find_secrets, redact
from secuscan.config import DEMO_PROJECT_DIR
from secuscan.ingest import SourceFile
from secuscan.models import Scan
from secuscan.pipeline import new_id
from secuscan.scoring import project_score

FAKE_KEY = "sk_test_UNITTESTFAKEKEY1234567890"


def _rules(language: str, code: str) -> set[str]:
    return {f.rule_id for f in analyze_file(SourceFile(f"x.{language}", language, code))}


def test_rules_each_language():
    assert "PY-SQLI" in _rules("python", 'cur.execute(f"SELECT * FROM t WHERE id = {uid}")')
    assert "JS-XSS" in _rules("javascript", "el.innerHTML = userInput;")
    assert "PHP-SQLI" in _rules("php", "mysqli_query($c, \"SELECT * FROM t WHERE id = \" . $_GET['id']);")
    assert "JAVA-SQLI" in _rules("java", 'stmt.executeQuery("SELECT * FROM t WHERE id = " + id);')


def test_parametrized_query_not_flagged():
    assert "PY-SQLI" not in _rules("python", 'cur.execute("SELECT * FROM t WHERE id = ?", (uid,))')
    assert "JAVA-SQLI" not in _rules("java", 'conn.prepareStatement("SELECT * FROM t WHERE id = ?");')


def test_comments_ignored():
    assert not _rules("python", "# cursor.execute(f\"SELECT {x}\")")


def test_secret_masked_and_redacted():
    source = SourceFile("config.js", "javascript", f'const key = "{FAKE_KEY}";\n')
    matches = find_secrets(source)
    assert len(matches) == 1
    assert matches[0].masked == "sk_test_****"
    assert FAKE_KEY not in redact(source, matches).content


def test_placeholder_passwords_ignored():
    source = SourceFile("s.py", "python", 'password = "changeme123"\ntoken = "${API_TOKEN_VALUE}"\n')
    assert find_secrets(source) == []


def test_secret_value_never_persisted(tmp_path, service):
    project = tmp_path / "proj"
    project.mkdir()
    (project / "app.py").write_text(
        f'STRIPE_KEY = "{FAKE_KEY}"\nDB_PASSWORD = "Unit-Test-Passw0rd!"\n', encoding="utf-8"
    )
    scan = Scan(id=new_id(), project_name="Acme test", source="upload")
    service.storage.save_scan(scan)
    findings = service.run(scan, project)
    assert {f.kind for f in findings} == {"secret"}
    dump = "\n".join(line for line in sqlite3.connect(service.storage.db_path).iterdump())
    assert FAKE_KEY not in dump
    assert "Unit-Test-Passw0rd!" not in dump


def test_demo_project_detects_all_languages(service):
    scan = Scan(id=new_id(), project_name="Acme Shop (démo)", source="demo")
    service.storage.save_scan(scan)
    findings = service.run(scan, DEMO_PROJECT_DIR)
    languages = {f.language for f in findings if f.kind == "sast"}
    assert languages == {"python", "javascript", "typescript", "php", "java"}
    assert sum(f.kind == "secret" for f in findings) == 4
    assert scan.status == "completed" and scan.score is not None


def test_dismissal_persists_across_scans(tmp_path, service):
    project = tmp_path / "proj"
    project.mkdir()
    (project / "app.py").write_text("import os\nos.system(cmd)\n", encoding="utf-8")
    first = Scan(id=new_id(), project_name="Acme", source="upload")
    service.storage.save_scan(first)
    finding = service.run(first, project)[0]
    service.storage.save_dismissal("Acme", finding.fingerprint, "accepted_risk", "Commande fixe interne.")

    (project / "app.py").write_text("import os\n\n\nos.system(cmd)\n", encoding="utf-8")  # ligne déplacée
    second = Scan(id=new_id(), project_name="Acme", source="upload")
    service.storage.save_scan(second)
    again = service.run(second, project)[0]
    assert again.status == "dismissed"
    assert second.summary.dismissed == 1


def test_score_bounds():
    assert project_score([]) == 100
