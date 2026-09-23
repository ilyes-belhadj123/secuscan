"""SS-23 — commande secuscan : configuration, seuil, codes retour, SARIF."""
import json

import pytest

from secuscan import cli
from secuscan.cli import EXIT_OK, EXIT_THRESHOLD, EXIT_USAGE, ConfigError, load_config


@pytest.fixture
def project(tmp_path, settings, monkeypatch):
    monkeypatch.setattr(cli, "get_settings", lambda: settings)  # pas de clé IA, OSV hors ligne
    root = tmp_path / "projet"
    (root / "src").mkdir(parents=True)
    (root / "tests").mkdir()
    (root / "src" / "app.py").write_text("import os\nos.system(cmd)\n", encoding="utf-8")        # critique
    (root / "src" / "crypto.py").write_text("import hashlib\nhashlib.md5(data)\n", encoding="utf-8")  # moyenne
    (root / "tests" / "test_app.py").write_text("eval(payload)\n", encoding="utf-8")
    return root


def test_threshold_exit_codes(project):
    assert cli.main(["scan", str(project)]) == EXIT_THRESHOLD           # défaut : high
    assert cli.main(["scan", str(project), "--fail-on", "none"]) == EXIT_OK


def test_config_file(project):
    (project / ".secuscan.yml").write_text(
        "fail_on: critical\nexclude:\n  - tests/\nignore_rules:\n  - PY-CMDI\n", encoding="utf-8"
    )
    assert cli.main(["scan", str(project)]) == EXIT_OK   # la seule alerte critique est ignorée
    assert cli.main(["scan", str(project), "--fail-on", "medium"]) == EXIT_THRESHOLD  # la ligne de commande prime


def test_exclude_removes_files(project, capsys):
    cli.main(["scan", str(project), "--fail-on", "none", "--exclude", "tests/", "--format", "json"])
    files = {f["file"] for f in json.loads(capsys.readouterr().out)["findings"]}
    assert files == {"src/app.py", "src/crypto.py"}


@pytest.mark.parametrize("content,message", [
    ("fail_on: sometimes\n", "fail_on"),
    ("unknown_key: 1\n", "inconnue"),
    ("exclude: tests\n", "liste"),
    ("ai: yes please\n", "true ou false"),
    ("- a\n- b\n", "objet"),
])
def test_invalid_config(tmp_path, content, message):
    path = tmp_path / ".secuscan.yml"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(ConfigError, match=message):
        load_config(path)


def test_invalid_config_exit_code(project):
    (project / ".secuscan.yml").write_text("fail_on: jamais\n", encoding="utf-8")
    assert cli.main(["scan", str(project)]) == EXIT_USAGE
    assert cli.main(["scan", str(project / "absent")]) == EXIT_USAGE


def test_yaml_is_loaded_safely(tmp_path):
    path = tmp_path / ".secuscan.yml"
    path.write_text("fail_on: !!python/object/apply:os.system ['echo pwned']\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(path)


def test_sarif_output(project, tmp_path):
    out = tmp_path / "rapport.sarif"
    cli.main(["scan", str(project), "--fail-on", "none", "--format", "sarif", "--output", str(out)])
    sarif = json.loads(out.read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert {"PY-CMDI", "PY-WEAKHASH"} <= rule_ids
    result = next(r for r in run["results"] if r["ruleId"] == "PY-CMDI")
    assert result["level"] == "error"
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "src/app.py"
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 2
    assert result["partialFingerprints"]["secuscanFingerprint/v1"]
    rule = next(r for r in run["tool"]["driver"]["rules"] if r["id"] == "PY-CMDI")
    assert rule["properties"]["security-severity"] == "9.5" and "CWE-78" in rule["properties"]["tags"]
