"""SS-1 (file d'analyses durable, workers) et SS-4 (analyse statique isolée)."""
import base64
import os
import threading
import time

import pytest
from conftest import register

from secuscan import pipeline, sandbox, worker
from secuscan.config import DEMO_PROJECT_DIR
from secuscan.ingest import Workspace
from secuscan.models import Scan
from secuscan.pipeline import CloneSpec, new_id
from secuscan.sandbox import SandboxError, StaticResult, analyze_static, child_env

TOKEN_KEY = base64.b64encode(b"k" * 32).decode()


@pytest.fixture
def queued(service):
    service.settings.secuscan_queue = "worker"
    service.settings.secuscan_token_key = TOKEN_KEY
    return service


def _key(findings):
    return sorted((f.kind, f.rule_id, f.file, f.start_line) for f in findings)


# ---------------------------------------------------------------------- SS-1 : file et workers
def test_api_enqueues_and_worker_runs(api, queued):
    client = register(api(), "jane.doe@example.com")
    scan = client.post("/api/scans/snippet", json={"filename": "app.py", "code": "import os\nos.system(cmd)\n",
                                                   "project_name": "Acme"}).json()
    assert client.get(f"/api/scans/{scan['id']}").json()["status"] == "queued"  # rien ne tourne dans l'API
    assert queued.storage.count_jobs("queued") == 1

    assert worker.process_one(queued, "w1") is True
    done = client.get(f"/api/scans/{scan['id']}").json()
    assert done["status"] == "completed" and done["summary"]["total"] == 1
    assert queued.storage.count_jobs("done") == 1 and worker.process_one(queued, "w1") is False
    assert not any(p.name.startswith("scan-") for p in queued.settings.work_dir.iterdir())  # code supprimé


def test_private_clone_access_is_encrypted_in_queue(queued, monkeypatch, tmp_path):
    captured = {}

    def fake_clone(url, branch, dest, settings, auth_header=None):
        captured["auth"] = auth_header
        dest.mkdir(parents=True)
        (dest / "app.py").write_text("eval(x)\n", encoding="utf-8")
    monkeypatch.setattr(pipeline, "clone_repository", fake_clone)

    scan = Scan(id=new_id(), project_name="Acme", source="git")
    workspace = Workspace(queued.settings.work_dir)
    queued.submit(scan, workspace.path / "src", workspace,
                  clone=CloneSpec("https://github.com/acme/app.git", "main", "Basic placeholder-secret-token"))
    with queued.storage._conn() as conn:
        payload = conn.execute("SELECT payload FROM jobs").fetchone()[0]
    assert "placeholder-secret-token" not in payload and '"auth": "v1:' in payload

    worker.process_one(queued, "w1")
    assert captured["auth"] == "Basic placeholder-secret-token"
    with queued.storage._conn() as conn:
        assert conn.execute("SELECT payload FROM jobs").fetchone()[0] == "{}"  # effacé après la tâche


def test_a_job_is_claimed_once(queued):
    queued.storage.enqueue_job("scan-1", {"root": "."})
    assert queued.storage.claim_job("w1")["scan_id"] == "scan-1"
    assert queued.storage.claim_job("w2") is None


def test_stale_job_is_retried_then_abandoned(queued):
    scan = Scan(id=new_id(), project_name="Acme", source="upload", status="running")
    queued.storage.save_scan(scan)
    queued.storage.enqueue_job(scan.id, {"root": "."})
    later = time.time() + worker.STALE_SECONDS + 1

    queued.storage.claim_job("w1")  # le worker w1 s'arrête sans finir
    assert worker.recover_stale(queued, now=later) == 1
    assert queued.storage.get_scan(scan.id).stage.startswith("En attente (reprise")
    queued.storage.claim_job("w2")  # deuxième tentative, même sort
    worker.recover_stale(queued, now=later + 1)
    failed = queued.storage.get_scan(scan.id)
    assert failed.status == "failed" and "relancez" in failed.error
    assert queued.storage.count_jobs("failed") == 1


def test_thread_mode_fails_scans_interrupted_by_a_restart(service):
    running = Scan(id=new_id(), project_name="Acme", source="upload", status="running")
    done = Scan(id=new_id(), project_name="Acme", source="upload", status="completed")
    for scan in (running, done):
        service.storage.save_scan(scan)
    leftover = Workspace(service.settings.work_dir)
    (leftover.path / "app.py").write_text("x = 1", encoding="utf-8")
    assert service.recover_interrupted() == 1
    assert service.storage.get_scan(running.id).status == "failed"
    assert "redémarrage" in service.storage.get_scan(running.id).error
    assert service.storage.get_scan(done.id).status == "completed"
    assert not leftover.path.exists()  # code importé supprimé


def test_only_the_owner_finishes_or_keeps_a_job(queued):
    storage = queued.storage
    storage.enqueue_job("scan-1", {"root": "."})
    job = storage.claim_job("w1")
    assert storage.heartbeat_job(job["id"], "w1")
    # Signe de vie récent : la tâche n'est pas reprise, même si la détection la croyait abandonnée
    assert not storage.requeue_job(job["id"], older_than=time.time() - 600)
    assert storage.requeue_job(job["id"], older_than=time.time() + 1)
    assert storage.claim_job("w2")["id"] == job["id"]
    # L'ancien worker ne peut plus ni signaler sa présence, ni terminer la tâche reprise par w2
    assert not storage.heartbeat_job(job["id"], "w1")
    assert not storage.finish_job(job["id"], "done", "w1")
    assert storage.finish_job(job["id"], "done", "w2")


def test_unreadable_job_fails_without_stopping_the_worker(queued):
    scan = Scan(id=new_id(), project_name="Acme", source="upload", status="queued")
    queued.storage.save_scan(scan)
    queued.storage.enqueue_job(scan.id, {"root": ".", "clone": {"url": "https://example.com/r.git", "auth": "abîmé"}})
    assert worker.process_one(queued, "w1") is True
    failed = queued.storage.get_scan(scan.id)
    assert failed.status == "failed" and "relancez" in failed.error
    assert queued.storage.count_jobs("failed") == 1


def test_worker_picks_up_ai_settings_changed_in_the_ui(queued):
    from secuscan.config import refresh_ai_settings
    env_file = queued.settings.secuscan_env_file
    env_file.write_text("OPENROUTER_MODEL=anthropic/claude-haiku-5-5\n", encoding="utf-8")
    assert refresh_ai_settings(queued.settings)
    assert queued.settings.openrouter_model == "anthropic/claude-haiku-5-5"
    assert not refresh_ai_settings(queued.settings)  # fichier inchangé : rien n'est relu
    env_file.write_text("OPENROUTER_MODEL=anthropic/claude-sonnet-5-5\n", encoding="utf-8")
    later = env_file.stat().st_mtime_ns + 10**9  # horloge de fichier grossière sous Windows
    os.utime(env_file, ns=(later, later))
    assert refresh_ai_settings(queued.settings) and queued.settings.openrouter_model == "anthropic/claude-sonnet-5-5"


# ---------------------------------------------------------------------- SS-4 : isolation
def test_static_result_round_trip(settings):
    result = analyze_static(DEMO_PROJECT_DIR, settings, "scan-x")
    again = StaticResult.from_json(result.to_json())
    assert _key(again.findings) == _key(result.findings) and again.redacted.keys() == result.redacted.keys()
    assert [d.name for d in again.dependencies] == [d.name for d in result.dependencies]


def test_child_environment_has_no_secrets(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-placeholder")
    monkeypatch.setenv("SECUSCAN_SMTP_PASSWORD", "placeholder")
    env = child_env()
    assert "OPENROUTER_API_KEY" not in env and not any(k.startswith("SECUSCAN_") for k in env)


def test_process_mode_matches_inline(settings, monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-placeholder")
    inline = analyze_static(DEMO_PROJECT_DIR, settings, "scan-x")
    isolated = sandbox.run_in_process(DEMO_PROJECT_DIR, settings, "scan-x", None)
    assert _key(isolated.findings) == _key(inline.findings) and isolated.lines_scanned == inline.lines_scanned
    # Les secrets détectés restent masqués dans ce qui sort de l'analyse isolée
    assert all(f.secret and "*" in f.secret.masked for f in isolated.findings if f.kind == "secret")


def test_container_mode_exchanges_files(settings, tmp_path):
    project = settings.work_dir / "scan-demo"
    project.mkdir()
    (project / "app.py").write_text("import os\nos.system(cmd)\n", encoding="utf-8")
    stop = threading.Event()

    def sandbox_container():  # le service « sandbox » de docker-compose
        while not stop.is_set():
            sandbox.serve_once(settings.sandbox_dir, [settings.work_dir])
            time.sleep(0.05)
    thread = threading.Thread(target=sandbox_container, daemon=True)
    thread.start()
    try:
        result = sandbox.run_in_container(project, settings, "scan-y", None, poll=0.05)
        assert [f.rule_id for f in result.findings] == ["PY-CMDI"]
        outside = tmp_path / "ailleurs"
        outside.mkdir()
        with pytest.raises(SandboxError, match="hors du périmètre"):
            sandbox.run_in_container(outside, settings, "scan-z", None, poll=0.05)
    finally:
        stop.set()
        thread.join()
    assert not list(settings.sandbox_dir.iterdir())  # aucun fichier d'échange ne traîne


def test_pipeline_uses_selected_mode(service, monkeypatch):
    calls = []
    real = sandbox.run_in_process
    monkeypatch.setattr(sandbox, "run_in_process", lambda *a: calls.append(a) or real(*a))
    service.settings.secuscan_sandbox = "process"
    scan = Scan(id=new_id(), project_name="Acme", source="demo")
    service.storage.save_scan(scan)
    findings = service.run(scan, DEMO_PROJECT_DIR)
    assert calls and scan.status == "completed" and findings
    assert os.environ.get("SECUSCAN_SANDBOX") is None
