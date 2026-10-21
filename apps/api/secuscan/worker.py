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

from .config import get_settings, refresh_ai_settings
from .ingest import Workspace
from .pipeline import CloneSpec, ScanService, job_aad
from .storage import Storage
from .tokenbox import decrypt

log = logging.getLogger(__name__)
HEARTBEAT_SECONDS = 30
STALE_SECONDS = 600
MAX_ATTEMPTS = 2


def _heartbeat(storage: Storage, job_id: str, worker_id: str, stop: threading.Event) -> None:
    # Une erreur passagère (base verrouillée) ne doit pas arrêter les signes de vie : la tâche serait
    # sinon reprise par un autre worker alors qu'elle tourne encore
    while not stop.wait(HEARTBEAT_SECONDS):
        try:
            if not storage.heartbeat_job(job_id, worker_id):
                log.warning("Tâche %s reprise par un autre worker", job_id)
                return
        except Exception:  # noqa: BLE001
            log.exception("Signe de vie de la tâche %s non enregistré", job_id)


def process_one(service: ScanService, worker_id: str) -> bool:
    """Exécute la plus ancienne tâche en attente ; False s'il n'y en a aucune."""
    storage = service.storage
    job = storage.claim_job(worker_id)
    if not job:
        return False
    if refresh_ai_settings(service.settings):
        log.info("Réglages IA rechargés (modèle %s)", service.settings.openrouter_model)
    scan = storage.get_scan(job["scan_id"])
    if scan is None:
        storage.finish_job(job["id"], "failed", worker_id)
        return True
    payload = job["payload"]
    try:
        clone = None
        if spec := payload.get("clone"):
            auth = (decrypt(spec["auth"], service.settings.secuscan_token_key, job_aad(scan.id))
                    if spec["auth"] else None)
            clone = CloneSpec(spec["url"], spec.get("branch"), auth)
        workspace = Workspace.existing(Path(payload["workspace"])) if payload.get("workspace") else None
    except Exception as exc:  # noqa: BLE001 — accès Git illisible (clé changée) : la tâche échoue, pas le worker
        log.exception("Tâche %s illisible", job["id"])
        scan.status, scan.stage = "failed", "Échec"
        scan.error = f"Analyse impossible à reprendre ({type(exc).__name__}) : relancez-la."
        storage.save_scan(scan)
        storage.finish_job(job["id"], "failed", worker_id)
        return True
    stop = threading.Event()
    threading.Thread(target=_heartbeat, args=(storage, job["id"], worker_id, stop), daemon=True).start()
    try:
        service._run_safely(scan, Path(payload["root"]), workspace, clone)
    finally:
        stop.set()
    done = storage.get_scan(scan.id)
    if not storage.finish_job(job["id"], "done" if done and done.status == "completed" else "failed", worker_id):
        log.warning("Tâche %s reprise par un autre worker pendant l'analyse : résultat de celui-ci conservé", job["id"])
    return True


def recover_stale(service: ScanService, now: float | None = None) -> int:
    """Remet en file les tâches d'un worker disparu ; abandonne après MAX_ATTEMPTS tentatives."""
    storage = service.storage
    threshold = (now or time.time()) - STALE_SECONDS
    stale = storage.stale_jobs(threshold)
    for job in stale:
        scan = storage.get_scan(job["scan_id"])
        if job["attempts"] >= MAX_ATTEMPTS:
            storage.finish_job(job["id"], "failed")
            if scan:
                scan.status, scan.stage = "failed", "Échec"
                scan.error = "Analyse interrompue à plusieurs reprises (worker arrêté) : relancez-la."
                storage.save_scan(scan)
        else:
            if not storage.requeue_job(job["id"], threshold):
                continue  # le worker a redonné signe de vie entre-temps
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
        try:
            if time.monotonic() - last_recovery > 60:
                recover_stale(service)
                last_recovery = time.monotonic()
            if process_one(service, worker_id):
                continue
        except Exception:  # noqa: BLE001 — une erreur ponctuelle (base verrouillée…) n'arrête pas le worker
            log.exception("Erreur du worker, nouvelle tentative dans %.0f s", max(args.poll, 5))
            time.sleep(max(args.poll, 5))
            continue
        if args.once:
            return 0
        time.sleep(args.poll)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    sys.exit(main())
