"""
CyberSec-CLI Normalized Database Schema
Version 2 - Replaces single output TEXT blob with normalized tables
"""

import sqlite3
import os

SCHEMA_VERSION = 2

def get_db_path():
    from web.main import SCANS_DB
    return SCANS_DB

def init_db_v2(conn: sqlite3.Connection):
    """Create all v2 schema tables. Safe to run multiple times."""
    c = conn.cursor()
    
    # Enable WAL mode for better concurrent read performance
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA foreign_keys=ON")
    
    # ── scans table (extended from v1) ──────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            uuid            TEXT UNIQUE NOT NULL,
            user_id         TEXT,
            timestamp       TEXT NOT NULL,
            target          TEXT NOT NULL,
            ip              TEXT,
            command         TEXT,
            scan_type       TEXT,
            status          TEXT DEFAULT 'completed',
            schema_version  INTEGER DEFAULT 2,
            raw_output      TEXT,
            output_format   TEXT DEFAULT 'json'
        )
    """)
    
    # ── scan_summary (one row per scan, denormalized counts) ────
    c.execute("""
        CREATE TABLE IF NOT EXISTS scan_summary (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id          INTEGER NOT NULL UNIQUE,
            open_port_count  INTEGER DEFAULT 0,
            max_cvss_score   REAL DEFAULT 0.0,
            critical_count   INTEGER DEFAULT 0,
            high_count       INTEGER DEFAULT 0,
            medium_count     INTEGER DEFAULT 0,
            low_count        INTEGER DEFAULT 0,
            cve_count        INTEGER DEFAULT 0,
            has_cves         INTEGER DEFAULT 0,
            total_ports_scanned INTEGER DEFAULT 0,
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
        )
    """)
    
    # ── scan_ports (one row per open port) ──────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS scan_ports (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id      INTEGER NOT NULL,
            port         INTEGER NOT NULL,
            protocol     TEXT DEFAULT 'tcp',
            service      TEXT,
            version      TEXT,
            banner       TEXT,
            risk         TEXT,
            cvss_score   REAL DEFAULT 0.0,
            confidence   REAL DEFAULT 0.0,
            tls_version  TEXT,
            http_status  INTEGER,
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
        )
    """)
    
    # ── scan_cves (one row per CVE per port) ────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS scan_cves (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            port_id     INTEGER NOT NULL,
            scan_id     INTEGER NOT NULL,
            cve_id      TEXT NOT NULL,
            cvss_score  REAL DEFAULT 0.0,
            severity    TEXT,
            FOREIGN KEY (port_id) REFERENCES scan_ports(id) ON DELETE CASCADE,
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
        )
    """)
    
    # ── indexes ──────────────────────────────────────────────────
    indexes = [
        "CREATE INDEX IF NOT EXISTS idx_scans_uuid         ON scans(uuid)",
        "CREATE INDEX IF NOT EXISTS idx_scans_user_id      ON scans(user_id)",
        "CREATE INDEX IF NOT EXISTS idx_scans_target       ON scans(target)",
        "CREATE INDEX IF NOT EXISTS idx_scans_timestamp    ON scans(timestamp)",
        "CREATE INDEX IF NOT EXISTS idx_summary_scan_id    ON scan_summary(scan_id)",
        "CREATE INDEX IF NOT EXISTS idx_summary_cvss       ON scan_summary(max_cvss_score)",
        "CREATE INDEX IF NOT EXISTS idx_summary_critical   ON scan_summary(critical_count)",
        "CREATE INDEX IF NOT EXISTS idx_ports_scan_id      ON scan_ports(scan_id)",
        "CREATE INDEX IF NOT EXISTS idx_ports_port         ON scan_ports(port)",
        "CREATE INDEX IF NOT EXISTS idx_ports_risk         ON scan_ports(risk)",
        "CREATE INDEX IF NOT EXISTS idx_cves_scan_id       ON scan_cves(scan_id)",
        "CREATE INDEX IF NOT EXISTS idx_cves_cve_id        ON scan_cves(cve_id)",
        "CREATE INDEX IF NOT EXISTS idx_cves_severity      ON scan_cves(severity)",
    ]
    for idx in indexes:
        c.execute(idx)
    
    _add_column_if_missing(c, "scans", "raw_output",      "TEXT")
    _add_column_if_missing(c, "scans", "output_format",   "TEXT DEFAULT 'json'")
    _add_column_if_missing(c, "scans", "schema_version",  "INTEGER DEFAULT 1")
    _add_column_if_missing(c, "scans", "scan_type",       "TEXT")
    _add_column_if_missing(c, "scans", "status",          "TEXT DEFAULT 'completed'")
    
    conn.commit()


def _add_column_if_missing(c, table, column, definition):
    """Safely add a column to an existing table."""
    try:
        c.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
    except sqlite3.OperationalError:
        pass  # Column already exists — safe to ignore
