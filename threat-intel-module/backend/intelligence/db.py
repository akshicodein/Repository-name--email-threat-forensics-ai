"""Threat Memory storage layer.

Hackathon build uses SQLite (zero setup). database/schema.sql has the
equivalent PostgreSQL schema for later migration — swap this connection
layer for psycopg without touching the rest of the module (see the
"Golden Rule" in the team rules doc: internal change freely, don't break
the input/output contract).
"""

import sqlite3
import os
from contextlib import contextmanager
from datetime import datetime, timezone

from backend.intelligence.config import settings

SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
    case_id TEXT PRIMARY KEY,
    email_id TEXT,
    attack_dna TEXT,
    classification TEXT,
    risk_score REAL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ip_observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    ip TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    FOREIGN KEY (case_id) REFERENCES cases(case_id)
);

CREATE TABLE IF NOT EXISTS domain_observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    domain TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    FOREIGN KEY (case_id) REFERENCES cases(case_id)
);

CREATE INDEX IF NOT EXISTS idx_ip_observations_ip ON ip_observations(ip);
CREATE INDEX IF NOT EXISTS idx_domain_observations_domain ON domain_observations(domain);
"""


def _ensure_dir():
    d = os.path.dirname(settings.DATABASE_PATH)
    if d and not os.path.exists(d):
        os.makedirs(d, exist_ok=True)


@contextmanager
def get_conn():
    _ensure_dir()
    conn = sqlite3.connect(settings.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with get_conn() as conn:
        conn.executescript(SCHEMA)


def save_case(case_id, email_id, attack_dna, classification, risk_score, ips, domains):
    """Insert/update a case and log its IP + domain observations (Threat Memory)."""
    now = datetime.now(timezone.utc).isoformat()
    with get_conn() as conn:
        existing = conn.execute(
            "SELECT created_at FROM cases WHERE case_id = ?", (case_id,)
        ).fetchone()
        created_at = existing["created_at"] if existing else now
        conn.execute(
            "INSERT OR REPLACE INTO cases (case_id, email_id, attack_dna, classification, risk_score, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (case_id, email_id, attack_dna, classification, risk_score, created_at),
        )
        for ip in ips:
            conn.execute(
                "INSERT INTO ip_observations (case_id, ip, observed_at) VALUES (?, ?, ?)",
                (case_id, ip, now),
            )
        for domain in domains:
            conn.execute(
                "INSERT INTO domain_observations (case_id, domain, observed_at) VALUES (?, ?, ?)",
                (case_id, domain, now),
            )


def find_cases_by_ip(ip: str, exclude_case_id: str | None = None) -> list[str]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT DISTINCT case_id FROM ip_observations WHERE ip = ? AND case_id != ?",
            (ip, exclude_case_id or ""),
        ).fetchall()
        return [r["case_id"] for r in rows]


def find_cases_by_domain(domain: str, exclude_case_id: str | None = None) -> list[str]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT DISTINCT case_id FROM domain_observations WHERE domain = ? AND case_id != ?",
            (domain, exclude_case_id or ""),
        ).fetchall()
        return [r["case_id"] for r in rows]


def all_cases(exclude_case_id: str | None = None) -> list[dict]:
    """All historical cases, used for Attack DNA similarity comparison."""
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM cases WHERE case_id != ? ORDER BY created_at ASC",
            (exclude_case_id or "",),
        ).fetchall()
        return [dict(r) for r in rows]


def ip_timeline(ips: list[str]) -> list[dict]:
    """Chronological domain/IP observations for the given IPs (infra evolution)."""
    if not ips:
        return []
    with get_conn() as conn:
        placeholders = ",".join("?" for _ in ips)
        q = f"""
        SELECT d.domain AS domain, io.ip AS ip, d.case_id AS case_id, d.observed_at AS observed_at
        FROM domain_observations d
        LEFT JOIN ip_observations io ON io.case_id = d.case_id
        WHERE io.ip IN ({placeholders})
        ORDER BY d.observed_at ASC
        """
        rows = conn.execute(q, ips).fetchall()
        return [dict(r) for r in rows]
