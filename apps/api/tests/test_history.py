"""Secrets dans l'historique Git (dépôt Git réel, temporaire, valeurs factices)."""
import shutil
import subprocess

import pytest

from secuscan import cli
from secuscan.analyzers.history import HISTORY_FILE, export_history, find_history_secrets
from secuscan.models import Scan
from secuscan.pipeline import new_id

pytestmark = pytest.mark.skipif(not shutil.which("git"), reason="git absent")
FAKE_AWS = "AKIA" + "Q7ZX3MPLW9RTB2KD"  # identifiant factice au format AWS


def _git(repo, *args):
    subprocess.run(["git", "-C", str(repo), "-c", "user.name=Jane Doe", "-c", "user.email=jane.doe@example.com",
                    "-c", "commit.gpgsign=false", *args], check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path):
    repo = tmp_path / "src"
    repo.mkdir()
    _git(repo, "init", "-q")
    (repo / "config.py").write_text(f'AWS_ACCESS_KEY_ID = "{FAKE_AWS}"\nDEBUG = False\n', encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "configuration")
    (repo / "config.py").write_text('import os\nAWS_ACCESS_KEY_ID = os.environ["AWS_ACCESS_KEY_ID"]\nDEBUG = False\n',
                                    encoding="utf-8")
    _git(repo, "commit", "-q", "-am", "secret retiré")
    return repo


def test_removed_secret_found_in_history(repo):
    out = repo.parent / HISTORY_FILE
    assert export_history(repo, out, 50)
    text = out.read_text(encoding="utf-8")
    assert "Jane Doe" not in text and "jane.doe@example.com" not in text and "configuration" not in text
    found = find_history_secrets(text, current=set())
    assert len(found) == 1
    h = found[0]
    assert h.path == "config.py" and h.line == 1 and len(h.commit) >= 7 and h.date
    assert FAKE_AWS not in h.redacted_line and "****" in h.redacted_line


def test_pipeline_reports_history_secret_masked(repo, service):
    out = repo.parent / HISTORY_FILE
    export_history(repo, out, 50)
    scan = Scan(id=new_id(), project_name="Acme", source="git")
    service.storage.save_scan(scan)
    findings = service.run(scan, repo, history_file=out)
    history = [f for f in findings if f.secret and f.secret.commit]
    assert len(history) == 1
    f = history[0]
    assert f.title.startswith("Secret dans l'historique Git") and "ne figure plus dans le code" in f.message
    assert FAKE_AWS not in f.snippet and FAKE_AWS not in f.model_dump_json()


def test_secret_still_in_code_is_not_duplicated(tmp_path):
    repo = tmp_path / "src"
    repo.mkdir()
    _git(repo, "init", "-q")
    (repo / "app.py").write_text(f'KEY = "{FAKE_AWS}"\n', encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "init")
    out = tmp_path / HISTORY_FILE
    export_history(repo, out, 50)
    from secuscan.analyzers import secrets
    from secuscan.ingest import SourceFile
    current = {m.fingerprint for m in secrets.find_secrets(SourceFile("app.py", "python", f'KEY = "{FAKE_AWS}"'))}
    assert find_history_secrets(out.read_text(encoding="utf-8"), current) == []


def test_no_history_without_git_dir(tmp_path):
    assert not export_history(tmp_path, tmp_path / HISTORY_FILE, 50)


def test_cli_reads_local_history(repo, tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "get_settings", lambda: cli.Settings(
        _env_file=None, secuscan_data_dir=tmp_path / "data", secuscan_offline=True))
    scan, findings = cli.run_scan(repo, cli.CliConfig(fail_on="none", offline=True))
    assert any(f.secret and f.secret.commit for f in findings)
    _, without = cli.run_scan(repo, cli.CliConfig(fail_on="none", offline=True, history=False))
    assert not any(f.secret and f.secret.commit for f in without)
