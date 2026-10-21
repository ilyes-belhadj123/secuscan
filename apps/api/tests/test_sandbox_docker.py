"""SS-4 — un conteneur jetable par analyse (sandbox_docker.py), avec un faux moteur Docker."""
import json
import struct
from pathlib import Path

import httpx
import pytest

from secuscan import sandbox
from secuscan.config import DEMO_PROJECT_DIR
from secuscan.sandbox import SandboxError
from secuscan.sandbox_docker import container_spec, demux, run_in_ephemeral_container


def frame(stream: int, text: str) -> bytes:
    data = text.encode()
    return bytes([stream, 0, 0, 0]) + struct.pack(">I", len(data)) + data


class FakeDocker:
    """Moteur Docker simulé : « exécute » le conteneur en traduisant le montage /scan."""

    def __init__(self, exit_code: int = 0):
        self.calls: list[tuple[str, str]] = []
        self.spec: dict = {}
        self.exit_code = exit_code
        self.output = b""

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path.removeprefix("/v1.45")
        self.calls.append((request.method, path))
        if path == "/containers/create":
            self.spec = json.loads(request.content)
            return httpx.Response(201, json={"Id": "c0ffee"})
        if path.endswith("/start"):
            self.output = self._run()
            return httpx.Response(204)
        if path.endswith("/wait"):
            return httpx.Response(200, json={"StatusCode": self.exit_code})
        if path.endswith("/logs"):
            return httpx.Response(200, content=self.output)
        if request.method == "DELETE":
            return httpx.Response(204)
        return httpx.Response(404)

    def _run(self) -> bytes:
        if self.exit_code:
            return frame(2, "MemoryError")
        cmd = self.spec["Cmd"]
        req = json.loads(cmd[cmd.index("--request") + 1])
        mounts = self.spec["HostConfig"]["Mounts"]
        host = Path(mounts[0]["Source"]) if mounts else DEMO_PROJECT_DIR.parent

        def translate(p):  # chemin du conteneur → chemin réel
            prefix = "/scan" if mounts else "/app/demo"
            return str(host / Path(p).relative_to(prefix)) if p else None
        req["root"], req["history"] = translate(req["root"]), translate(req.get("history"))
        result = sandbox._handle(req, [host])
        return frame(2, "INFO journal\n") + frame(1, result.to_json())


def client(fake: FakeDocker) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(fake))


def scan_dir(settings, name="scan-abc"):
    project = settings.work_dir / name / "repo"
    project.mkdir(parents=True)
    (project / "app.py").write_text("import os\nos.system(cmd)\n", encoding="utf-8")
    return project


def test_container_is_locked_down_and_sees_only_its_scan(settings):
    spec = container_spec(scan_dir(settings), settings, "scan-1", ["tests/"])
    host = spec["HostConfig"]
    assert spec["NetworkDisabled"] and host["NetworkMode"] == "none"
    assert host["ReadonlyRootfs"] and host["CapDrop"] == ["ALL"] and not host["Privileged"]
    assert "no-new-privileges:true" in host["SecurityOpt"] and host["PidsLimit"] and host["Memory"]
    [mount] = host["Mounts"]
    assert mount["ReadOnly"] and mount["Type"] == "bind" and Path(mount["Source"]).name == "scan-abc"
    request = json.loads(spec["Cmd"][spec["Cmd"].index("--request") + 1])
    assert request["root"] == "/scan/repo" and request["exclude"] == ["tests/"]
    # Aucun secret dans ce qui part vers le conteneur
    assert not any("KEY" in e or "TOKEN" in e or "PASSWORD" in e for e in spec["Env"])
    assert "openrouter" not in json.dumps(spec).lower()


def test_named_volume_mounts_only_the_scan_subfolder(settings):
    settings.secuscan_sandbox_volume = "secuscan-work"
    [mount] = container_spec(scan_dir(settings), settings, "scan-1", None)["HostConfig"]["Mounts"]
    assert mount["Type"] == "volume" and mount["Source"] == "secuscan-work"
    assert mount["VolumeOptions"]["Subpath"] == "scan-abc" and mount["ReadOnly"]


def test_paths_outside_the_scan_are_refused(settings, tmp_path):
    with pytest.raises(SandboxError, match="hors du périmètre"):
        container_spec(tmp_path, settings, "scan-1", None)
    with pytest.raises(SandboxError, match="Historique"):
        container_spec(scan_dir(settings), settings, "scan-1", None, history_file=tmp_path / "h.txt")
    # Démonstration : embarquée dans l'image, aucun montage
    spec = container_spec(DEMO_PROJECT_DIR, settings, "scan-1", None)
    assert spec["HostConfig"]["Mounts"] == [] and "/app/demo/acme-shop" in spec["Cmd"][-1]


def test_round_trip_and_container_always_removed(settings):
    fake = FakeDocker()
    project = scan_dir(settings)
    history = project.parent / ".secuscan-history.txt"
    history.write_text("", encoding="utf-8")
    result = run_in_ephemeral_container(project, settings, "scan-1", None, history, client=client(fake))
    assert [f.rule_id for f in result.findings] == ["PY-CMDI"]
    assert json.loads(fake.spec["Cmd"][-1])["history"] == "/scan/.secuscan-history.txt"
    assert ("DELETE", "/containers/c0ffee") in fake.calls

    failing = FakeDocker(exit_code=137)
    with pytest.raises(SandboxError, match="mémoire"):
        run_in_ephemeral_container(project, settings, "scan-2", None, client=client(failing))
    assert ("DELETE", "/containers/c0ffee") in failing.calls


def test_docker_unreachable_is_a_clear_error(settings):
    def refuse(request):
        raise httpx.ConnectError("refusé")
    broken = httpx.Client(transport=httpx.MockTransport(refuse))
    with pytest.raises(SandboxError, match="Moteur Docker injoignable"):
        run_in_ephemeral_container(scan_dir(settings), settings, "scan-1", None, client=broken)


def test_demux_separates_streams():
    assert demux(frame(1, "a") + frame(2, "err") + frame(1, "b")) == ("ab", "err")


def test_run_command_accepts_request_argument(settings, capsys):
    project = scan_dir(settings)
    request = json.dumps(sandbox._request(project, settings, "scan-1", None))
    assert sandbox.main(["run", "--allow", str(settings.work_dir), "--request", request]) == 0
    assert "PY-CMDI" in capsys.readouterr().out
    with pytest.raises(SandboxError, match="hors du périmètre"):
        sandbox.main(["run", "--allow", str(project / "ailleurs"), "--request", request])
