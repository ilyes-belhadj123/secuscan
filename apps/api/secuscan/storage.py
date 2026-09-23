"""Stockage SQLite pour la démo (remplaçable par MongoDB : même interface)."""
import json
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path

from .models import Finding, Scan, now_iso

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    project_name TEXT NOT NULL,
    created_at TEXT NOT NULL,
    data TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    data TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE TABLE IF NOT EXISTS dismissals (
    project_name TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    reason TEXT NOT NULL,
    justification TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (project_name, fingerprint)
);
CREATE TABLE IF NOT EXISTS cache (
    namespace TEXT NOT NULL,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (namespace, key)
);
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    details TEXT NOT NULL
);
"""


class Storage:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._lock = threading.Lock()
        with self._conn() as conn:
            conn.executescript(_SCHEMA)

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.execute("PRAGMA journal_mode=WAL")
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    # --- Scans ---------------------------------------------------------
    def save_scan(self, scan: Scan) -> None:
        with self._lock, self._conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO scans (id, project_name, created_at, data) VALUES (?, ?, ?, ?)",
                (scan.id, scan.project_name, scan.created_at, scan.model_dump_json()),
            )

    def get_scan(self, scan_id: str) -> Scan | None:
        with self._conn() as conn:
            row = conn.execute("SELECT data FROM scans WHERE id = ?", (scan_id,)).fetchone()
        return Scan.model_validate_json(row[0]) if row else None

    def list_scans(self) -> list[Scan]:
        with self._conn() as conn:
            rows = conn.execute("SELECT data FROM scans ORDER BY created_at DESC").fetchall()
        return [Scan.model_validate_json(r[0]) for r in rows]

    def previous_completed_scan(self, project_name: str, before: str) -> Scan | None:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT data FROM scans WHERE project_name = ? AND created_at < ? ORDER BY created_at DESC",
                (project_name, before),
            ).fetchall()
        for (data,) in rows:
            scan = Scan.model_validate_json(data)
            if scan.status == "completed":
                return scan
        return None

    # --- Findings ------------------------------------------------------
    def save_findings(self, findings: list[Finding]) -> None:
        with self._lock, self._conn() as conn:
            conn.executemany(
                "INSERT OR REPLACE INTO findings (id, scan_id, data) VALUES (?, ?, ?)",
                [(f.id, f.scan_id, f.model_dump_json()) for f in findings],
            )

    def list_findings(self, scan_id: str) -> list[Finding]:
        with self._conn() as conn:
            rows = conn.execute("SELECT data FROM findings WHERE scan_id = ?", (scan_id,)).fetchall()
        return [Finding.model_validate_json(r[0]) for r in rows]

    def get_finding(self, finding_id: str) -> Finding | None:
        with self._conn() as conn:
            row = conn.execute("SELECT data FROM findings WHERE id = ?", (finding_id,)).fetchone()
        return Finding.model_validate_json(row[0]) if row else None

    # --- Alertes ignorées ----------------------------------------------
    def save_dismissal(self, project_name: str, fingerprint: str, reason: str, justification: str) -> None:
        with self._lock, self._conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO dismissals VALUES (?, ?, ?, ?, ?)",
                (project_name, fingerprint, reason, justification, now_iso()),
            )

    def dismissals_for(self, project_name: str) -> dict[str, tuple[str, str]]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT fingerprint, reason, justification FROM dismissals WHERE project_name = ?",
                (project_name,),
            ).fetchall()
        return {fp: (reason, justification) for fp, reason, justification in rows}

    # --- Cache clé/valeur (IA, advisories) -----------------------------
    def cache_get(self, namespace: str, key: str):
        with self._conn() as conn:
            row = conn.execute(
                "SELECT value FROM cache WHERE namespace = ? AND key = ?", (namespace, key)
            ).fetchone()
        return json.loads(row[0]) if row else None

    def cache_set(self, namespace: str, key: str, value) -> None:
        with self._lock, self._conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO cache VALUES (?, ?, ?, ?)",
                (namespace, key, json.dumps(value, ensure_ascii=False), now_iso()),
            )

    # --- Journal d'audit (append-only) ---------------------------------
    def audit(self, action: str, target: str, details: dict | None = None) -> None:
        with self._lock, self._conn() as conn:
            conn.execute(
                "INSERT INTO audit_logs (ts, action, target, details) VALUES (?, ?, ?, ?)",
                (now_iso(), action, target, json.dumps(details or {}, ensure_ascii=False)),
            )

    def list_audit(self, limit: int = 200) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT ts, action, target, details FROM audit_logs ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [{"ts": ts, "action": a, "target": t, "details": json.loads(d)} for ts, a, t, d in rows]
