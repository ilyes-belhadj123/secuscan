"""SS-1 — worker de la file d'analyses (SECUSCAN_QUEUE=worker).

Usage (dans apps/api) :  uv run python -m secuscan.worker [--once]

Plusieurs workers peuvent tourner en parallèle (sur la même base) : chaque tâche n'est réservée que
par un seul. Une analyse survit au redémarrage de l'API. Si un worker s'arrête en pleine analyse,
sa tâche est reprise par un autre après STALE_SECONDS (au plus MAX_ATTEMPTS fois).
"""
import argparse
import logging
import os
import socket
import sys
import threading
import time
from pathlib import Path

from .config import get_settings
from .ingest import Workspace
from .pipeline import CloneSpec, ScanService, job_aad
from .storage import Storage
from .tokenbox import decrypt

log = logging.getLogger(__name__)
HEARTBEAT_SECONDS = 30
STALE_SECONDS = 600
MAX_ATTEMPTS = 2


def _heartbeat(storage: Storage, job_id: str, stop: threading.Event) -> None:
    while not stop.wait(HEARTBEAT_SECONDS):
        storage.heartbeat_job(job_id)


def process_one(service: ScanService, worker_id: str) -> bool:
    """Exécute la plus ancienne tâche en attente ; False s'il n'y en a aucune."""
    storage = service.storage
    job = storage.claim_job(worker_id)
    if not job:
        return False
    scan = storage.get_scan(job["scan_id"])
    if scan is None:
        storage.finish_job(job["id"], "failed")
        return True
    payload = job["payload"]
    clone = None
    if spec := payload.get("clone"):
        auth = decrypt(spec["auth"], service.settings.secuscan_token_key, job_aad(scan.id)) if spec["auth"] else None
        clone = CloneSpec(spec["url"], spec.get("branch"), auth)
    workspace = Workspace.existing(Path(payload["workspace"])) if payload.get("workspace") else None
    stop = threading.Event()
    threading.Thread(target=_heartbeat, args=(storage, job["id"], stop), daemon=True).start()
    try:
        service._run_safely(scan, Path(payload["root"]), workspace, clone)
    finally:
        stop.set()
    done = storage.get_scan(scan.id)
    storage.finish_job(job["id"], "done" if done and done.status == "completed" else "failed")
    return True


def recover_stale(service: ScanService, now: float | None = None) -> int:
    """Remet en file les tâches d'un worker disparu ; abandonne après MAX_ATTEMPTS tentatives."""
    storage = service.storage
    stale = storage.stale_jobs((now or time.time()) - STALE_SECONDS)
    for job in stale:
        scan = storage.get_scan(job["scan_id"])
        if job["attempts"] >= MAX_ATTEMPTS:
            storage.finish_job(job["id"], "failed")
            if scan:
                scan.status, scan.stage = "failed", "Échec"
                scan.error = "Analyse interrompue à plusieurs reprises (worker arrêté) : relancez-la."
                storage.save_scan(scan)
        else:
            storage.requeue_job(job["id"])
            if scan:
                scan.status, scan.stage = "queued", "En attente (reprise après interruption)"
                storage.save_scan(scan)
        log.warning("Tâche %s reprise (tentative %d)", job["id"], job["attempts"])
    return len(stale)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="secuscan.worker", description="Worker de la file d'analyses SecuScan")
    parser.add_argument("--once", action="store_true", help="traiter les tâches en attente puis s'arrêter")
    parser.add_argument("--poll", type=float, default=1.0, help="intervalle d'attente sans tâche (secondes)")
    args = parser.parse_args(argv)
    settings = get_settings()
    service = ScanService(settings, Storage(settings.data_dir / "secuscan.db"))
    worker_id = f"{socket.gethostname()}:{os.getpid()}"
    log.info("Worker %s prêt (isolation de l'analyse statique : %s)", worker_id, settings.secuscan_sandbox)
    last_recovery = 0.0
    while True:
        if time.monotonic() - last_recovery > 60:
            recover_stale(service)
            last_recovery = time.monotonic()
        if process_one(service, worker_id):
            continue
        if args.once:
            return 0
        time.sleep(args.poll)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    sys.exit(main())
