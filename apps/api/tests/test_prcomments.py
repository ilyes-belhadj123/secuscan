"""SS-22 — commentaires automatiques sur les pull requests (API GitHub / GitLab simulées)."""
import json

import httpx
import pytest

from secuscan import cli
from secuscan.models import Scan
from secuscan.pipeline import new_id
from secuscan.prcomments import (
    SUMMARY_MARKER,
    GitHub,
    GitLab,
    PRCommentError,
    _fenced,
    added_lines,
    marker,
    provider_from_env,
    publish,
)

# app.py : la PR ajoute les lignes 3 et 4 ; la ligne 2 (déjà présente) n'est pas commentée
APP = "import os\nos.system(old)\nos.system(cmd)\neval(expr)\n"
PATCH = "@@ -1,2 +1,4 @@\n import os\n os.system(old)\n+os.system(cmd)\n+eval(expr)"


def test_added_lines():
    patch = "@@ -10,3 +10,4 @@ def f():\n a\n-b\n+B\n+C\n c\n\\ No newline at end of file\n@@ -40 +41 @@\n+z"
    assert added_lines(patch) == {11, 12, 41}
    assert added_lines("") == set()


def test_fence_cannot_be_closed_by_content():
    assert _fenced("x = '```'", "diff").startswith("````diff\n")


@pytest.fixture
def scanned(service, tmp_path):
    project = tmp_path / "p"
    project.mkdir()
    (project / "app.py").write_text(APP)
    scan = Scan(id=new_id(), project_name="Acme", source="upload")
    service.storage.save_scan(scan)
    return scan, service.run(scan, project)


class FakeGitHub:
    def __init__(self):
        self.review_comments: list[dict] = []
        self.issue_comments: list[dict] = []
        self.reviews = 0
        self.forged: list[dict] = []  # commentaires d'un participant qui recopie nos marqueurs

    def handler(self, request: httpx.Request) -> httpx.Response:
        path, method = request.url.path, request.method
        assert request.headers["authorization"] == "Bearer gh-placeholder-token"
        if path.endswith("/pulls/7/files"):
            return httpx.Response(200, json=[{"filename": "app.py", "patch": PATCH}])
        if path.endswith("/pulls/7/comments"):
            bot = [{**c, "user": {"login": "github-actions[bot]"}} for c in self.review_comments]
            return httpx.Response(200, json=bot + self.forged)
        if path.endswith("/pulls/7/reviews") and method == "POST":
            body = json.loads(request.content)
            assert body["commit_id"] == "abc123" and body["event"] == "COMMENT"
            self.reviews += 1
            self.review_comments += body["comments"]
            return httpx.Response(200, json={})
        if path.endswith("/issues/7/comments") and method == "GET":
            return httpx.Response(200, json=self.forged + self.issue_comments)
        if path.endswith("/issues/7/comments") and method == "POST":
            self.issue_comments.append({"id": 1, "body": json.loads(request.content)["body"],
                                        "user": {"login": "github-actions[bot]"}})
            return httpx.Response(201, json={})
        if path.endswith("/issues/comments/1") and method == "PATCH":
            self.issue_comments[0]["body"] = json.loads(request.content)["body"]
            return httpx.Response(200, json={})
        return httpx.Response(404)


def _github_env(tmp_path) -> dict:
    event = tmp_path / "event.json"
    event.write_text(json.dumps({"pull_request": {"number": 7, "head": {"sha": "abc123"}}}))
    return {"GITHUB_ACTIONS": "true", "GITHUB_TOKEN": "gh-placeholder-token", "GITHUB_REPOSITORY": "acme/shop",
            "GITHUB_EVENT_PATH": str(event)}


def test_github_comments_changed_lines_only_and_once(scanned, tmp_path):
    scan, findings = scanned
    fake = FakeGitHub()
    client = httpx.Client(base_url="https://api.github.com", transport=httpx.MockTransport(fake.handler),
                          headers={"Authorization": "Bearer gh-placeholder-token"})
    gh = GitHub.from_env(_github_env(tmp_path), client=client)
    # Un participant poste les marqueurs de SecuScan (alertes et synthèse) : ils sont ignorés
    forged = "".join(marker(f) for f in findings) + SUMMARY_MARKER
    fake.forged = [{"id": 99, "body": forged, "user": {"login": "mallory"}}]

    publish(gh, scan, findings, "high", blockers=2)
    lines = sorted(c["line"] for c in fake.review_comments)
    assert lines == [3, 4]  # la ligne 2 n'est pas modifiée par la PR
    assert all(c["path"] == "app.py" and c["side"] == "RIGHT" for c in fake.review_comments)
    assert "SecuScan" in fake.review_comments[0]["body"] and "<!-- secuscan:" in fake.review_comments[0]["body"]
    assert len(fake.issue_comments) == 1 and SUMMARY_MARKER in fake.issue_comments[0]["body"]
    assert "Seuil « high » dépassé" in fake.issue_comments[0]["body"]

    # Nouvelle exécution : rien n'est commenté deux fois, la synthèse est mise à jour (pas dupliquée)
    message = publish(gh, scan, findings, "high", blockers=0)
    assert fake.reviews == 1 and len(fake.review_comments) == 2
    assert len(fake.issue_comments) == 1 and "Aucune alerte au niveau du seuil" in fake.issue_comments[0]["body"]
    assert "0 en ligne" in message


def test_gitlab_discussions(scanned):
    scan, findings = scanned
    discussions: list[dict] = []
    notes: list[dict] = []
    refs = {"base_sha": "b", "start_sha": "s", "head_sha": "h"}
    forged = "".join(marker(f) for f in findings)

    def handler(request: httpx.Request) -> httpx.Response:
        path, method = request.url.path, request.method
        assert request.headers["private-token"] == "gl-placeholder-token"
        base = "/api/v4/projects/42/merge_requests/5"
        if path == base:
            return httpx.Response(200, json={"diff_refs": refs})
        if path == "/api/v4/user":
            return httpx.Response(200, json={"id": 7})
        if path == f"{base}/diffs":
            return httpx.Response(200, json=[{"new_path": "app.py", "diff": PATCH}])
        if path == f"{base}/discussions" and method == "GET":
            return httpx.Response(200, json=[{"notes": [{"body": d["body"], "author": {"id": 7}}]} for d in discussions]
                                  + [{"notes": [{"body": forged, "author": {"id": 666}}]}])
        if path == f"{base}/discussions":
            body = json.loads(request.content)
            assert body["position"]["head_sha"] == "h" and body["position"]["new_path"] == "app.py"
            discussions.append(body)
            return httpx.Response(201, json={})
        if path == f"{base}/notes" and method == "GET":
            return httpx.Response(200, json=[{"id": 66, "body": SUMMARY_MARKER, "author": {"id": 666}}] + notes)
        if path == f"{base}/notes":
            notes.append({"id": 9, "body": json.loads(request.content)["body"], "author": {"id": 7}})
            return httpx.Response(201, json={})
        if path == f"{base}/notes/9" and method == "PUT":
            notes[0]["body"] = json.loads(request.content)["body"]
            return httpx.Response(200, json={})
        return httpx.Response(404)

    env = {"SECUSCAN_GITLAB_TOKEN": "gl-placeholder-token", "CI_API_V4_URL": "https://gitlab.example.com/api/v4",
           "CI_PROJECT_ID": "42", "CI_MERGE_REQUEST_IID": "5"}
    client = httpx.Client(base_url=env["CI_API_V4_URL"], transport=httpx.MockTransport(handler),
                          headers={"PRIVATE-TOKEN": "gl-placeholder-token"})
    gl = GitLab.from_env(env, client=client)
    publish(gl, scan, findings, "high", blockers=1)
    publish(gl, scan, findings, "high", blockers=1)
    assert sorted(d["position"]["new_line"] for d in discussions) == [3, 4]
    assert len(notes) == 1 and SUMMARY_MARKER in notes[0]["body"]


@pytest.mark.parametrize("env, message", [
    ({}, "GitHub Actions ou GitLab CI"),
    ({"GITHUB_ACTIONS": "true"}, "GITHUB_TOKEN"),
    ({"GITLAB_CI": "true", "SECUSCAN_GITLAB_TOKEN": "t", "CI_API_V4_URL": "u", "CI_PROJECT_ID": "1"},
     "pas lancé par une merge request"),
])
def test_provider_errors(env, message):
    with pytest.raises(PRCommentError, match=message):
        provider_from_env(env)


def test_github_push_event_is_not_a_pr(tmp_path):
    env = _github_env(tmp_path)
    (tmp_path / "event.json").write_text(json.dumps({"ref": "refs/heads/main"}))
    with pytest.raises(PRCommentError, match="pas lancé par une pull request"):
        provider_from_env(env)


def test_cli_publication_failure_keeps_verdict(tmp_path, monkeypatch, capsys):
    for name in ("GITHUB_ACTIONS", "GITLAB_CI"):
        monkeypatch.delenv(name, raising=False)
    project = tmp_path / "p"
    project.mkdir()
    (project / "app.py").write_text(APP)
    monkeypatch.setenv("SECUSCAN_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setattr(cli, "get_settings", lambda: cli.Settings(
        _env_file=None, secuscan_data_dir=tmp_path / "data", secuscan_offline=True))
    code = cli.main(["scan", str(project), "--offline", "--pr-comment", "--fail-on", "high"])
    assert code == cli.EXIT_THRESHOLD
    assert "Commentaires de PR non publiés" in capsys.readouterr().err
