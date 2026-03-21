"""
Centralized database connection factory.
- If DATABASE_URL is set → PostgreSQL via asyncpg
- Otherwise → SQLite with FK + WAL enabled
"""
import os
import sqlite3
from typing import Optional

try:
    import asyncpg
    HAS_ASYNCPG = True
except ImportError:
    HAS_ASYNCPG = False

DATABASE_URL = os.getenv("DATABASE_URL")


def get_sqlite_conn(db_path: str) -> sqlite3.Connection:
    """Return a sqlite3 connection with FK enforcement and WAL mode enabled."""
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def is_postgres() -> bool:
    """Return True if PostgreSQL is configured."""
    return bool(DATABASE_URL and HAS_ASYNCPG)


async def get_postgres_conn():
    """Return an asyncpg connection. Raises if DATABASE_URL not set."""
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL not set")
    if not HAS_ASYNCPG:
        raise RuntimeError("asyncpg not installed: pip install asyncpg")
    return await asyncpg.connect(DATABASE_URL)


# ── PostgreSQL schema (mirrors SQLite v2) ──────────────────────────────────

PG_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id              SERIAL PRIMARY KEY,
    uuid            TEXT UNIQUE NOT NULL,
    user_id         TEXT,
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    target          TEXT NOT NULL,
    ip              TEXT,
    command         TEXT,
    scan_type       TEXT,
    status          TEXT DEFAULT 'completed',
    schema_version  INTEGER DEFAULT 2,
    raw_output      TEXT,
    output_format   TEXT DEFAULT 'json'
);
CREATE INDEX IF NOT EXISTS idx_scans_uuid    ON scans(uuid);
CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans(user_id);

CREATE TABLE IF NOT EXISTS scan_summary (
    id               SERIAL PRIMARY KEY,
    scan_id          INTEGER NOT NULL UNIQUE REFERENCES scans(id) ON DELETE CASCADE,
    open_port_count  INTEGER DEFAULT 0,
    max_cvss_score   REAL DEFAULT 0.0,
    critical_count   INTEGER DEFAULT 0,
    high_count       INTEGER DEFAULT 0,
    medium_count     INTEGER DEFAULT 0,
    low_count        INTEGER DEFAULT 0,
    cve_count        INTEGER DEFAULT 0,
    has_cves         INTEGER DEFAULT 0,
    total_ports_scanned INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS scan_ports (
    id          SERIAL PRIMARY KEY,
    scan_id     INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    port        INTEGER NOT NULL,
    protocol    TEXT DEFAULT 'tcp',
    service     TEXT,
    version     TEXT,
    banner      TEXT,
    risk        TEXT DEFAULT 'LOW',
    cvss_score  REAL DEFAULT 0.0,
    confidence  REAL DEFAULT 0.0,
    tls_version TEXT,
    http_status INTEGER
);

CREATE TABLE IF NOT EXISTS scan_cves (
    id          SERIAL PRIMARY KEY,
    port_id     INTEGER NOT NULL REFERENCES scan_ports(id) ON DELETE CASCADE,
    scan_id     INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    cve_id      TEXT NOT NULL,
    cvss_score  REAL DEFAULT 0.0,
    severity    TEXT DEFAULT 'LOW'
);
"""


async def init_postgres():
    """Create all tables in PostgreSQL if they don't exist."""
    if not is_postgres():
        return
    conn = await get_postgres_conn()
    try:
        await conn.execute(PG_SCHEMA)
    finally:
        await conn.close()
