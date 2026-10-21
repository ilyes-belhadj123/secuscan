"""SS-4 — un conteneur jetable par analyse (SECUSCAN_SANDBOX=ephemeral).

Le worker demande au moteur Docker (API HTTP sur le socket Unix, sans client `docker` dans l'image)
de créer un conteneur neuf pour chaque analyse, détruit juste après :

- aucun réseau, système de fichiers en lecture seule, aucun privilège ni capacité, mémoire, nombre
  de processus et durée limités ;
- il ne voit que le dossier de **cette** analyse, monté en lecture seule sur /scan : une analyse ne
  peut ni lire ni modifier le code d'une autre (contrairement au conteneur partagé « container ») ;
- la demande (chemins et réglages, sans aucun secret) est passée en argument, le résultat lu sur sa
  sortie standard.

Montage du dossier d'analyse, vu depuis le moteur Docker :
- SECUSCAN_SANDBOX_VOLUME renseigné : sous-dossier du volume nommé qui contient le dossier des
  analyses (worker dans docker-compose ; Docker Engine 26 ou plus) ;
- sinon : montage direct du chemin (worker lancé directement sur le serveur).
"""
import json
import logging
import struct
from pathlib import Path, PurePosixPath

import httpx

from .config import DEMO_PROJECT_DIR, Settings
from .sandbox import SANDBOX_MEMORY_BYTES, SANDBOX_TIMEOUT_SECONDS, SandboxError, StaticResult, _request, new_id

log = logging.getLogger(__name__)
API = "http://docker/v1.45"  # Docker Engine 26 : montage d'un sous-dossier de volume
MOUNT_POINT = PurePosixPath("/scan")
# Démonstration : code embarqué dans l'image, rien à monter
IMAGE_DEMO_DIR = PurePosixPath("/app/demo")


def _client(settings: Settings) -> httpx.Client:
    transport = httpx.HTTPTransport(uds=settings.secuscan_docker_socket)
    return httpx.Client(transport=transport, timeout=httpx.Timeout(30, read=SANDBOX_TIMEOUT_SECONDS + 30))


def _scan_mount(root: Path, settings: Settings) -> tuple[dict | None, Path | None, PurePosixPath]:
    """(montage Docker, dossier monté, chemin de `root` dans le conteneur)."""
    root, work = root.resolve(), settings.work_dir.resolve()
    if root.is_relative_to(work) and root != work:
        rel = root.relative_to(work)
        scan_dir = work / rel.parts[0]  # dossier de cette analyse uniquement (code + historique Git)
        inside = MOUNT_POINT.joinpath(*rel.parts[1:])
        if settings.secuscan_sandbox_volume:
            mount = {"Type": "volume", "Source": settings.secuscan_sandbox_volume, "Target": str(MOUNT_POINT),
                     "ReadOnly": True, "VolumeOptions": {"NoCopy": True, "Subpath": rel.parts[0]}}
        else:
            mount = {"Type": "bind", "Source": str(scan_dir), "Target": str(MOUNT_POINT), "ReadOnly": True}
        return mount, scan_dir, inside
    demo = DEMO_PROJECT_DIR.parent.resolve()
    if root.is_relative_to(demo):
        return None, None, IMAGE_DEMO_DIR.joinpath(*root.relative_to(demo).parts)
    raise SandboxError(f"Dossier hors du périmètre autorisé : {root}")


def container_spec(root: Path, settings: Settings, scan_id: str, exclude: list[str] | None,
                   history_file: Path | None = None) -> dict:
    """Corps de la création du conteneur (POST /containers/create)."""
    mount, scan_dir, inside = _scan_mount(root, settings)
    request = _request(root, settings, scan_id, exclude, None)
    request["root"] = str(inside)
    if history_file:
        if not scan_dir or not history_file.resolve().is_relative_to(scan_dir):
            raise SandboxError(f"Historique Git hors du dossier de l'analyse : {history_file}")
        request["history"] = str(MOUNT_POINT.joinpath(*history_file.resolve().relative_to(scan_dir).parts))
    allowed = str(MOUNT_POINT if mount else IMAGE_DEMO_DIR)
    return {
        "Image": settings.secuscan_sandbox_image,
        "Cmd": ["python", "-m", "secuscan.sandbox", "run", "--allow", allowed, "--request", json.dumps(request)],
        "Env": ["SECUSCAN_PRODUCTION=false", "PYTHONIOENCODING=utf-8"],  # aucun secret
        "User": "10001:10001",
        "NetworkDisabled": True,
        "Labels": {"secuscan.scan": scan_id},
        "HostConfig": {
            "NetworkMode": "none",
            "ReadonlyRootfs": True,
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges:true"],
            "Privileged": False,
            "Memory": SANDBOX_MEMORY_BYTES,
            "MemorySwap": SANDBOX_MEMORY_BYTES,  # pas de swap en plus
            "PidsLimit": 256,
            "NanoCpus": 2_000_000_000,
            # secuscan: ignore[BANDIT-B108] /tmp du conteneur jetable : en mémoire, propre à l'analyse, non exécutable
            "Tmpfs": {"/tmp": "rw,noexec,nosuid,size=256m"},
            "Mounts": [mount] if mount else [],
            "LogConfig": {"Type": "json-file", "Config": {}},  # sortie relue par l'API Docker
        },
    }


def demux(raw: bytes) -> tuple[str, str]:
    """Sortie standard et erreur d'un conteneur sans terminal (flux multiplexé de l'API Docker)."""
    out, err, pos = bytearray(), bytearray(), 0
    while pos + 8 <= len(raw):
        stream, size = raw[pos], struct.unpack(">I", raw[pos + 4:pos + 8])[0]
        chunk = raw[pos + 8:pos + 8 + size]
        (err if stream == 2 else out).extend(chunk)
        pos += 8 + size
    return out.decode("utf-8", "replace"), err.decode("utf-8", "replace")


def run_in_ephemeral_container(root: Path, settings: Settings, scan_id: str, exclude: list[str] | None,
                               history_file: Path | None = None, client: httpx.Client | None = None) -> StaticResult:
    spec = container_spec(root, settings, scan_id, exclude, history_file)
    docker = client or _client(settings)
    name = f"secuscan-scan-{new_id()}"
    try:
        created = docker.post(f"{API}/containers/create", params={"name": name}, json=spec)
    except httpx.TransportError as exc:
        raise SandboxError(f"Moteur Docker injoignable ({settings.secuscan_docker_socket}) : {exc}") from exc
    if created.status_code >= 400:
        raise SandboxError(f"Création du conteneur d'analyse refusée : {created.text[-300:]}")
    container = created.json()["Id"]
    try:
        docker.post(f"{API}/containers/{container}/start").raise_for_status()
        try:
            status = docker.post(f"{API}/containers/{container}/wait", params={"condition": "not-running"},
                                 timeout=httpx.Timeout(30, read=SANDBOX_TIMEOUT_SECONDS))
        except httpx.TimeoutException as exc:
            raise SandboxError("Analyse statique interrompue : durée maximale dépassée.") from exc
        code = status.json().get("StatusCode", 1)
        logs = docker.get(f"{API}/containers/{container}/logs", params={"stdout": 1, "stderr": 1})
        stdout, stderr = demux(logs.content)
        if code != 0:
            hint = " (mémoire maximale dépassée ?)" if code == 137 else ""
            raise SandboxError(f"Analyse statique isolée en échec, code {code}{hint} : {stderr.strip()[-300:]}")
        return StaticResult.from_json(stdout)
    except httpx.HTTPError as exc:
        raise SandboxError(f"Conteneur d'analyse : erreur du moteur Docker : {exc}") from exc
    finally:
        try:  # le conteneur est détruit dans tous les cas (même arrêté de force)
            docker.delete(f"{API}/containers/{container}", params={"force": "true", "v": "true"})
        except httpx.HTTPError:
            log.warning("Conteneur %s non supprimé", name)
        if client is None:
            docker.close()
