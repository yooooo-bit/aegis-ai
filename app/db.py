"""SQLite storage: scans, findings, and a tamper-evident audit log."""
import hashlib
import json
import sqlite3
from datetime import datetime, timezone

import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    mode TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    error TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id),
    title TEXT, risk TEXT, confidence TEXT, url TEXT, param TEXT,
    description TEXT, solution TEXT, cwe TEXT, plugin_id TEXT, evidence TEXT,
    priority_score INTEGER, priority_label TEXT,
    evidence_hash TEXT
);
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
);
CREATE TABLE IF NOT EXISTS analyses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id),
    group_key TEXT NOT NULL,
    source TEXT NOT NULL,
    explanation TEXT, impact TEXT, remediation TEXT,
    verified INTEGER DEFAULT 1,
    model TEXT, note TEXT, created_at TEXT,
    UNIQUE(scan_id, group_key)
);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT,
    detail TEXT,
    prev_hash TEXT,
    entry_hash TEXT
);
"""


HASH_FIELDS = ("title", "risk", "confidence", "url", "param", "description", "solution", "cwe",
               "plugin_id", "evidence", "priority_score", "priority_label")


def finding_hash(f) -> str:
    """SHA-256 over a finding's content fields (text as str, score as int) so it can be re-checked later."""
    payload = {k: (int(f[k]) if k == "priority_score" else ("" if f[k] is None else str(f[k]))) for k in HASH_FIELDS}
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class _Conn(sqlite3.Connection):
    """`with connect() as conn:` commits (or rolls back) AND closes the connection."""

    def __exit__(self, exc_type, exc, tb):
        try:
            return super().__exit__(exc_type, exc, tb)
        finally:
            self.close()


def connect():
    conn = sqlite3.connect(config.DB_PATH, factory=_Conn)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with connect() as conn:
        conn.executescript(SCHEMA)
        # Scans run in background threads, so any scan still "running" at startup was interrupted.
        conn.execute(
            "UPDATE scans SET status='failed', finished_at=?, error=? WHERE status='running'",
            (now(), "Interrupted: the app was restarted while this scan was running."),
        )


def get_running_scan():
    with connect() as conn:
        return conn.execute("SELECT * FROM scans WHERE status='running' ORDER BY id DESC LIMIT 1").fetchone()


def audit(action: str, target: str = "", detail: str = ""):
    """Append a hash-chained audit entry (each row hashes the previous one)."""
    with connect() as conn:
        row = conn.execute("SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
        prev = row["entry_hash"] if row else "GENESIS"
        ts = now()
        payload = f"{prev}|{ts}|{action}|{target}|{detail}"
        entry_hash = hashlib.sha256(payload.encode()).hexdigest()
        conn.execute(
            "INSERT INTO audit_log (ts, action, target, detail, prev_hash, entry_hash) VALUES (?,?,?,?,?,?)",
            (ts, action, target, detail, prev, entry_hash),
        )


def verify_audit_chain() -> bool:
    with connect() as conn:
        prev = "GENESIS"
        for r in conn.execute("SELECT * FROM audit_log ORDER BY id"):
            payload = f"{prev}|{r['ts']}|{r['action']}|{r['target']}|{r['detail']}"
            if hashlib.sha256(payload.encode()).hexdigest() != r["entry_hash"] or r["prev_hash"] != prev:
                return False
            prev = r["entry_hash"]
    return True


def create_scan(target: str, mode: str) -> int:
    with connect() as conn:
        cur = conn.execute(
            "INSERT INTO scans (target, mode, status, started_at) VALUES (?,?,?,?)",
            (target, mode, "running", now()),
        )
        return cur.lastrowid


def finish_scan(scan_id: int, status: str, error: str = None):
    with connect() as conn:
        conn.execute(
            "UPDATE scans SET status=?, finished_at=?, error=? WHERE id=?",
            (status, now(), error, scan_id),
        )


def save_findings(scan_id: int, findings: list):
    with connect() as conn:
        for f in findings:
            f["evidence_hash"] = finding_hash(f)
            conn.execute(
                """INSERT INTO findings
                (scan_id, title, risk, confidence, url, param, description, solution, cwe,
                 plugin_id, evidence, priority_score, priority_label, evidence_hash)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (scan_id, f["title"], f["risk"], f["confidence"], f["url"], f["param"],
                 f["description"], f["solution"], f["cwe"], f["plugin_id"], f["evidence"],
                 f["priority_score"], f["priority_label"], f["evidence_hash"]),
            )


def list_scans():
    with connect() as conn:
        return conn.execute(
            """SELECT s.*, (SELECT COUNT(*) FROM findings f WHERE f.scan_id = s.id) AS finding_count
               FROM scans s ORDER BY s.id DESC"""
        ).fetchall()


def upsert_analysis(scan_id, group_key, source, explanation, impact, remediation,
                    verified=1, model=None, note=None):
    with connect() as conn:
        conn.execute(
            """INSERT INTO analyses
               (scan_id, group_key, source, explanation, impact, remediation, verified, model, note, created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(scan_id, group_key) DO UPDATE SET
                 source=excluded.source, explanation=excluded.explanation, impact=excluded.impact,
                 remediation=excluded.remediation, verified=excluded.verified, model=excluded.model,
                 note=excluded.note, created_at=excluded.created_at""",
            (scan_id, group_key, source, explanation, impact, remediation, verified, model, note, now()),
        )


def set_analysis_note(scan_id, group_key, note):
    with connect() as conn:
        conn.execute("UPDATE analyses SET note=? WHERE scan_id=? AND group_key=?", (note, scan_id, group_key))


def get_analyses(scan_id) -> dict:
    with connect() as conn:
        rows = conn.execute("SELECT * FROM analyses WHERE scan_id=?", (scan_id,)).fetchall()
    return {r["group_key"]: r for r in rows}


def get_previous_scan(scan):
    """The most recent earlier completed scan of the same target (used for retest comparison)."""
    with connect() as conn:
        return conn.execute(
            "SELECT * FROM scans WHERE status='completed' AND target=? AND id<? ORDER BY id DESC LIMIT 1",
            (scan["target"], scan["id"]),
        ).fetchone()


def get_latest_completed_scan():
    with connect() as conn:
        return conn.execute(
            "SELECT * FROM scans WHERE status='completed' ORDER BY id DESC LIMIT 1"
        ).fetchone()


def get_trend(limit: int = 12):
    """Findings per completed scan, oldest first (for the trend chart)."""
    with connect() as conn:
        rows = conn.execute(
            """SELECT s.id, s.started_at,
                      COUNT(f.id) AS total,
                      COALESCE(SUM(CASE WHEN f.priority_label IN ('Critical','High') THEN 1 ELSE 0 END), 0) AS urgent
               FROM scans s LEFT JOIN findings f ON f.scan_id = s.id
               WHERE s.status = 'completed'
               GROUP BY s.id ORDER BY s.id DESC LIMIT ?""",
            (limit,),
        ).fetchall()
    return list(reversed(rows))


def get_overview() -> dict:
    with connect() as conn:
        scans = conn.execute("SELECT COUNT(*) AS c FROM scans").fetchone()["c"]
        findings = conn.execute("SELECT COUNT(*) AS c FROM findings").fetchone()["c"]
        urgent = conn.execute(
            "SELECT COUNT(*) AS c FROM findings WHERE priority_label IN ('Critical','High')"
        ).fetchone()["c"]
    return {"scans": scans, "findings": findings, "urgent": urgent}


def get_scan(scan_id: int):
    with connect() as conn:
        return conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()


def get_findings(scan_id: int):
    with connect() as conn:
        return conn.execute(
            "SELECT * FROM findings WHERE scan_id=? ORDER BY priority_score DESC", (scan_id,)
        ).fetchall()


def get_audit_chain():
    """The whole audit log, oldest first (used for evidence export)."""
    with connect() as conn:
        return conn.execute("SELECT * FROM audit_log ORDER BY id").fetchall()


def get_audit_by_action(action: str, limit: int = 20):
    with connect() as conn:
        return conn.execute(
            "SELECT * FROM audit_log WHERE action=? ORDER BY id DESC LIMIT ?", (action, limit)
        ).fetchall()


def get_audit_log(limit: int = 50):
    with connect() as conn:
        return conn.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
