"""Stockage SQLite (remplaçable par MongoDB : même interface).

Multi-tenant (SS-2) : les analyses, alertes ignorées et entrées d'audit portent un `org_id`.
Les données sans organisation (org_id = "") sont celles des outils internes (benchmark,
préparation de la démo) : elles ne sont visibles d'aucune organisation. Le cache (IA, OSV) est
partagé : il est indexé par l'empreinte du contenu envoyé, il ne révèle donc rien qu'un
utilisateur ne possède déjà.
"""
import json
import sqlite3
import threading
import time
import uuid
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
CREATE TABLE IF NOT EXISTS org_dismissals (
    org_id TEXT NOT NULL,
    project_name TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    reason TEXT NOT NULL,
    justification TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (org_id, project_name, fingerprint)
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
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS organizations (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS memberships (
    org_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    role TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (org_id, user_id)
);
CREATE TABLE IF NOT EXISTS invitations (
    id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    org_id TEXT NOT NULL,
    email TEXT NOT NULL,
    role TEXT NOT NULL,
    invited_by TEXT NOT NULL,
    expires_at REAL NOT NULL,
    accepted_at TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS invoices (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    number TEXT NOT NULL,
    period TEXT NOT NULL,
    plan TEXT NOT NULL,
    seats INTEGER NOT NULL,
    unit_price_eur REAL NOT NULL,
    amount_eur REAL NOT NULL,
    status TEXT NOT NULL,
    provider TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    org_id TEXT NOT NULL,
    expires_at REAL NOT NULL,
    created_at TEXT NOT NULL
);
"""

# Colonnes ajoutées après la première version (migration automatique des bases existantes)
_ADDED_COLUMNS = {
    "scans": [("org_id", "TEXT NOT NULL DEFAULT ''")],
    "audit_logs": [("org_id", "TEXT NOT NULL DEFAULT ''"), ("actor", "TEXT NOT NULL DEFAULT ''")],
    "organizations": [("plan", "TEXT NOT NULL DEFAULT 'free'")],
}


def _id() -> str:
    return uuid.uuid4().hex[:16]


class Storage:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._lock = threading.Lock()
        with self._conn() as conn:
            conn.executescript(_SCHEMA)
            for table, columns in _ADDED_COLUMNS.items():
                existing = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
                for name, decl in columns:
                    if name not in existing:
                        conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_org ON scans(org_id, created_at)")
            # Reprise des alertes ignorées de la première version (sans organisation)
            conn.execute(
                "INSERT OR IGNORE INTO org_dismissals SELECT '', project_name, fingerprint, reason, "
                "justification, created_at FROM dismissals"
            )
            conn.execute("DELETE FROM dismissals")

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
                "INSERT OR REPLACE INTO scans (id, project_name, created_at, data, org_id) VALUES (?, ?, ?, ?, ?)",
                (scan.id, scan.project_name, scan.created_at, scan.model_dump_json(), scan.org_id or ""),
            )

    def get_scan(self, scan_id: str, org_id: str | None = None) -> Scan | None:
        """Analyse par identifiant ; si `org_id` est fourni, uniquement si elle appartient à cette organisation."""
        query, params = "SELECT data FROM scans WHERE id = ?", [scan_id]
        if org_id is not None:
            query, params = query + " AND org_id = ?", params + [org_id]
        with self._conn() as conn:
            row = conn.execute(query, params).fetchone()
        return Scan.model_validate_json(row[0]) if row else None

    def list_scans(self, org_id: str | None = None) -> list[Scan]:
        """Analyses d'une organisation (toutes si org_id est None : outils internes uniquement)."""
        query, params = "SELECT data FROM scans", []
        if org_id is not None:
            query, params = query + " WHERE org_id = ?", [org_id]
        with self._conn() as conn:
            rows = conn.execute(query + " ORDER BY created_at DESC", params).fetchall()
        return [Scan.model_validate_json(r[0]) for r in rows]

    def previous_completed_scan(self, project_name: str, before: str, org_id: str = "") -> Scan | None:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT data FROM scans WHERE org_id = ? AND project_name = ? AND created_at < ? "
                "ORDER BY created_at DESC",
                (org_id, project_name, before),
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
    def save_dismissal(
        self, project_name: str, fingerprint: str, reason: str, justification: str, org_id: str = ""
    ) -> None:
        with self._lock, self._conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO org_dismissals VALUES (?, ?, ?, ?, ?, ?)",
                (org_id, project_name, fingerprint, reason, justification, now_iso()),
            )

    def dismissals_for(self, project_name: str, org_id: str = "") -> dict[str, tuple[str, str]]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT fingerprint, reason, justification FROM org_dismissals WHERE org_id = ? AND project_name = ?",
                (org_id, project_name),
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

    # --- Journal d'audit (append-only : aucune méthode de modification ni de suppression) ----
    def audit(self, action: str, target: str, details: dict | None = None, org_id: str = "", actor: str = "") -> None:
        with self._lock, self._conn() as conn:
            conn.execute(
                "INSERT INTO audit_logs (ts, action, target, details, org_id, actor) VALUES (?, ?, ?, ?, ?, ?)",
                (now_iso(), action, target, json.dumps(details or {}, ensure_ascii=False), org_id, actor),
            )

    def list_audit(self, org_id: str, limit: int = 200) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT ts, action, target, details, actor FROM audit_logs WHERE org_id = ? ORDER BY id DESC LIMIT ?",
                (org_id, limit),
            ).fetchall()
        return [
            {"ts": ts, "action": a, "target": t, "details": json.loads(d), "actor": actor}
            for ts, a, t, d, actor in rows
        ]

    # --- Utilisateurs --------------------------------------------------
    def create_user(self, email: str, name: str, password_hash: str) -> dict:
        user = {"id": _id(), "email": email, "name": name, "created_at": now_iso()}
        with self._lock, self._conn() as conn:
            conn.execute(
                "INSERT INTO users (id, email, name, password_hash, created_at) VALUES (?, ?, ?, ?, ?)",
                (user["id"], email, name, password_hash, user["created_at"]),
            )
        return user

    def get_user_by_email(self, email: str) -> dict | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT id, email, name, password_hash FROM users WHERE email = ?", (email,)
            ).fetchone()
        return dict(zip(("id", "email", "name", "password_hash"), row, strict=True)) if row else None

    def get_user(self, user_id: str) -> dict | None:
        with self._conn() as conn:
            row = conn.execute("SELECT id, email, name FROM users WHERE id = ?", (user_id,)).fetchone()
        return dict(zip(("id", "email", "name"), row, strict=True)) if row else None

    # --- Organisations et adhésions ------------------------------------
    def create_org(self, name: str, plan: str = "free") -> dict:
        org = {"id": _id(), "name": name, "created_at": now_iso(), "plan": plan}
        with self._lock, self._conn() as conn:
            conn.execute(
                "INSERT INTO organizations (id, name, created_at, plan) VALUES (?, ?, ?, ?)",
                (org["id"], name, org["created_at"], plan),
            )
        return org

    def get_org(self, org_id: str) -> dict | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT id, name, created_at, plan FROM organizations WHERE id = ?", (org_id,)
            ).fetchone()
        return dict(zip(("id", "name", "created_at", "plan"), row, strict=True)) if row else None

    def set_org_plan(self, org_id: str, plan: str) -> None:
        with self._lock, self._conn() as conn:
            conn.execute("UPDATE organizations SET plan = ? WHERE id = ?", (plan, org_id))

    # --- Quotas (SS-20) ------------------------------------------------
    def count_scans_since(self, org_id: str, since_iso: str) -> int:
        with self._conn() as conn:
            return conn.execute(
                "SELECT COUNT(*) FROM scans WHERE org_id = ? AND created_at >= ?", (org_id, since_iso)
            ).fetchone()[0]

    def project_names(self, org_id: str) -> set[str]:
        with self._conn() as conn:
            rows = conn.execute("SELECT DISTINCT project_name FROM scans WHERE org_id = ?", (org_id,)).fetchall()
        return {r[0] for r in rows}

    # --- Factures (SS-20) ----------------------------------------------
    def create_invoice(self, org_id: str, period: str, plan: str, seats: int, unit_price: float,
                       status: str, provider: str) -> dict:
        with self._lock, self._conn() as conn:
            count = conn.execute("SELECT COUNT(*) FROM invoices").fetchone()[0]
            invoice = {
                "id": _id(), "org_id": org_id, "number": f"SS-{period.replace('-', '')}-{count + 1:04d}",
                "period": period, "plan": plan, "seats": seats, "unit_price_eur": unit_price,
                "amount_eur": round(seats * unit_price, 2), "status": status, "provider": provider,
                "created_at": now_iso(),
            }
            conn.execute(
                "INSERT INTO invoices VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                tuple(invoice[k] for k in ("id", "org_id", "number", "period", "plan", "seats", "unit_price_eur",
                                           "amount_eur", "status", "provider", "created_at")),
            )
        return invoice

    def list_invoices(self, org_id: str) -> list[dict]:
        keys = ("id", "number", "period", "plan", "seats", "unit_price_eur", "amount_eur", "status", "provider",
                "created_at")
        with self._conn() as conn:
            rows = conn.execute(
                f"SELECT {', '.join(keys)} FROM invoices WHERE org_id = ? ORDER BY created_at DESC", (org_id,)
            ).fetchall()
        return [dict(zip(keys, r, strict=True)) for r in rows]

    def count_orgs(self) -> int:
        with self._conn() as conn:
            return conn.execute("SELECT COUNT(*) FROM organizations").fetchone()[0]

    def add_membership(self, org_id: str, user_id: str, role: str) -> None:
        with self._lock, self._conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO memberships VALUES (?, ?, ?, ?)", (org_id, user_id, role, now_iso())
            )

    def get_role(self, org_id: str, user_id: str) -> str | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT role FROM memberships WHERE org_id = ? AND user_id = ?", (org_id, user_id)
            ).fetchone()
        return row[0] if row else None

    def memberships_of(self, user_id: str) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT o.id, o.name, m.role FROM memberships m JOIN organizations o ON o.id = m.org_id "
                "WHERE m.user_id = ? ORDER BY o.name",
                (user_id,),
            ).fetchall()
        return [{"org_id": i, "name": n, "role": r} for i, n, r in rows]

    def list_members(self, org_id: str) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT u.id, u.email, u.name, m.role, m.created_at FROM memberships m "
                "JOIN users u ON u.id = m.user_id WHERE m.org_id = ? ORDER BY m.created_at",
                (org_id,),
            ).fetchall()
        return [dict(zip(("id", "email", "name", "role", "joined_at"), r, strict=True)) for r in rows]

    def remove_membership(self, org_id: str, user_id: str) -> None:
        with self._lock, self._conn() as conn:
            conn.execute("DELETE FROM memberships WHERE org_id = ? AND user_id = ?", (org_id, user_id))
            conn.execute("DELETE FROM sessions WHERE org_id = ? AND user_id = ?", (org_id, user_id))

    def count_owners(self, org_id: str) -> int:
        with self._conn() as conn:
            return conn.execute(
                "SELECT COUNT(*) FROM memberships WHERE org_id = ? AND role = 'owner'", (org_id,)
            ).fetchone()[0]

    def claim_orphan_data(self, org_id: str) -> int:
        """Rattache à la première organisation les analyses créées avant l'arrivée des comptes."""
        with self._lock, self._conn() as conn:
            rows = conn.execute(
                "SELECT id, data FROM scans WHERE org_id = '' AND project_name NOT LIKE 'benchmark:%'"
            ).fetchall()
            for scan_id, data in rows:
                scan = Scan.model_validate_json(data)
                scan.org_id = org_id
                conn.execute("UPDATE scans SET org_id = ?, data = ? WHERE id = ?", (org_id, scan.model_dump_json(), scan_id))
            conn.execute("UPDATE org_dismissals SET org_id = ? WHERE org_id = ''", (org_id,))
            conn.execute("UPDATE audit_logs SET org_id = ? WHERE org_id = ''", (org_id,))
        return len(rows)

    # --- Invitations ---------------------------------------------------
    def create_invitation(
        self, org_id: str, email: str, role: str, token_hash: str, expires_at: float, invited_by: str
    ) -> dict:
        inv = {"id": _id(), "org_id": org_id, "email": email, "role": role, "expires_at": expires_at}
        with self._lock, self._conn() as conn:
            conn.execute(
                "INSERT INTO invitations VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?)",
                (inv["id"], token_hash, org_id, email, role, invited_by, expires_at, now_iso()),
            )
        return inv

    def get_invitation(self, token_hash: str) -> dict | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT id, org_id, email, role, expires_at, accepted_at FROM invitations WHERE token_hash = ?",
                (token_hash,),
            ).fetchone()
        keys = ("id", "org_id", "email", "role", "expires_at", "accepted_at")
        return dict(zip(keys, row, strict=True)) if row else None

    def list_invitations(self, org_id: str) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT id, email, role, expires_at, created_at FROM invitations "
                "WHERE org_id = ? AND accepted_at IS NULL AND expires_at > ? ORDER BY created_at DESC",
                (org_id, time.time()),
            ).fetchall()
        return [dict(zip(("id", "email", "role", "expires_at", "created_at"), r, strict=True)) for r in rows]

    def accept_invitation(self, invitation_id: str) -> None:
        with self._lock, self._conn() as conn:
            conn.execute("UPDATE invitations SET accepted_at = ? WHERE id = ?", (now_iso(), invitation_id))

    def revoke_invitation(self, invitation_id: str, org_id: str) -> bool:
        with self._lock, self._conn() as conn:
            cur = conn.execute(
                "DELETE FROM invitations WHERE id = ? AND org_id = ? AND accepted_at IS NULL", (invitation_id, org_id)
            )
        return cur.rowcount > 0

    # --- Sessions ------------------------------------------------------
    def create_session(self, token_hash: str, user_id: str, org_id: str, expires_at: float) -> None:
        with self._lock, self._conn() as conn:
            conn.execute(
                "INSERT INTO sessions VALUES (?, ?, ?, ?, ?)", (token_hash, user_id, org_id, expires_at, now_iso())
            )

    def get_session(self, token_hash: str) -> dict | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT user_id, org_id, expires_at FROM sessions WHERE token_hash = ?", (token_hash,)
            ).fetchone()
        if not row:
            return None
        session = dict(zip(("user_id", "org_id", "expires_at"), row, strict=True))
        if session["expires_at"] < time.time():
            self.delete_session(token_hash)
            return None
        return session

    def set_session_org(self, token_hash: str, org_id: str) -> None:
        with self._lock, self._conn() as conn:
            conn.execute("UPDATE sessions SET org_id = ? WHERE token_hash = ?", (org_id, token_hash))

    def delete_session(self, token_hash: str) -> None:
        with self._lock, self._conn() as conn:
            conn.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
