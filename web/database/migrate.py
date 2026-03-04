"""
One-time migration: scans.output TEXT blob → normalized tables
Safe to run multiple times (idempotent via schema_version check)
"""

import sqlite3
import json
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

RISK_TO_SEVERITY = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH", 
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM", 
    "low": "LOW",
}

def _parse_cvss_to_severity(cvss: float) -> str:
    if cvss >= 9.0: return "CRITICAL"
    if cvss >= 7.0: return "HIGH"
    if cvss >= 4.0: return "MEDIUM"
    return "LOW"


def _parse_output(output: str) -> Optional[Dict]:
    """Try to parse output as JSON. Returns None if plain text."""
    if not output:
        return None
    stripped = output.strip()
    if not stripped.startswith('{'):
        return None
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        return None


def _migrate_single_scan(
    conn: sqlite3.Connection,
    scan_id: int,
    scan_uuid: str,
    output: str,
    current_target: str,
) -> bool:
    """
    Migrate one scan's output blob to normalized tables.
    Returns True if migrated as JSON, False if kept as text.
    """
    c = conn.cursor()
    data = _parse_output(output)
    
    if data is None:
        # Plain text output (CLI scans) — preserve in raw_output
        c.execute("""
            UPDATE scans 
            SET raw_output = ?, output_format = 'text', schema_version = 2
            WHERE id = ?
        """, (output, scan_id))
        
        # Insert empty summary so scan shows in queries
        c.execute("""
            INSERT OR IGNORE INTO scan_summary 
            (scan_id, open_port_count, max_cvss_score, 
             critical_count, high_count, medium_count, low_count,
             cve_count, has_cves, total_ports_scanned)
            VALUES (?, 0, 0.0, 0, 0, 0, 0, 0, 0, 0)
        """, (scan_id,))
        return False
    
    # ── Parse JSON scan data ─────────────────────────────────────
    open_ports = data.get("open_ports", [])
    total_ports_scanned = data.get("total_ports_scanned", 0)
    
    # Counters for summary
    critical_count = high_count = medium_count = low_count = 0
    cve_count = 0
    max_cvss = 0.0
    
    for port_data in open_ports:
        port_num  = port_data.get("port")
        service   = port_data.get("service")
        version   = port_data.get("version")
        banner    = port_data.get("banner", "")[:500]  # cap banner size
        risk      = port_data.get("risk") or port_data.get("severity", "")
        cvss      = float(port_data.get("cvss_score") or 0.0)
        confidence = float(port_data.get("confidence") or 0.0)
        protocol  = port_data.get("protocol", "tcp")
        
        # TLS info
        tls_info   = port_data.get("tls_info") or {}
        tls_version = tls_info.get("tls_version") if tls_info else None
        
        # HTTP info
        http_info  = port_data.get("http_info") or {}
        http_status = http_info.get("status_code") if http_info else None
        
        # Track max CVSS
        if cvss > max_cvss:
            max_cvss = cvss
        
        # Normalise risk → severity bucket
        normalised_risk = RISK_TO_SEVERITY.get(risk, risk)
        if normalised_risk == "CRITICAL": critical_count += 1
        elif normalised_risk == "HIGH":   high_count += 1
        elif normalised_risk == "MEDIUM": medium_count += 1
        else:                             low_count += 1
        
        # Insert port row
        c.execute("""
            INSERT INTO scan_ports
            (scan_id, port, protocol, service, version, banner,
             risk, cvss_score, confidence, tls_version, http_status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (scan_id, port_num, protocol, service, version, banner,
              normalised_risk, cvss, confidence, tls_version, http_status))
        
        port_id = c.lastrowid
        
        # Insert CVE rows
        vulnerabilities = port_data.get("vulnerabilities", [])
        for cve in vulnerabilities:
            if not cve:
                continue
            cve_id = cve if isinstance(cve, str) else cve.get("cve_id", "")
            cve_cvss = float(
                cve.get("cvss_score", 0.0) if isinstance(cve, dict) else cvss
            )
            cve_severity = _parse_cvss_to_severity(cve_cvss)
            
            c.execute("""
                INSERT INTO scan_cves (port_id, scan_id, cve_id, cvss_score, severity)
                VALUES (?, ?, ?, ?, ?)
            """, (port_id, scan_id, cve_id, cve_cvss, cve_severity))
            cve_count += 1
    
    # Insert summary row
    c.execute("""
        INSERT OR REPLACE INTO scan_summary
        (scan_id, open_port_count, max_cvss_score,
         critical_count, high_count, medium_count, low_count,
         cve_count, has_cves, total_ports_scanned)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        scan_id,
        len(open_ports),
        round(max_cvss, 2),
        critical_count, high_count, medium_count, low_count,
        cve_count, 1 if cve_count > 0 else 0,
        total_ports_scanned
    ))
    
    # Update scan row — preserve raw_output, mark migrated
    c.execute("""
        UPDATE scans
        SET raw_output = ?, output_format = 'json', schema_version = 2,
            scan_type = ?
        WHERE id = ?
    """, (output, data.get("scan_type"), scan_id))
    
    return True


def run_migration(db_path: str) -> Dict[str, int]:
    """
    Run full migration. Returns stats dict.
    Safe to run multiple times — skips already migrated scans.
    """
    stats = {"total": 0, "migrated_json": 0, "migrated_text": 0, "skipped": 0, "errors": 0}
    
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA journal_mode=WAL")
    
    # Check if output column exists (old schema) or raw_output (new schema)
    c = conn.cursor()
    c.execute("PRAGMA table_info(scans)")
    columns = {row[1] for row in c.fetchall()}
    has_old_output = "output" in columns
    
    # Determine which column to read from
    output_column = "output" if has_old_output else "raw_output"
    
    try:
        # Fetch all scans not yet migrated (schema_version < 2 or NULL)
        c = conn.cursor()
        c.execute(f"""
            SELECT id, uuid, target, {output_column} 
            FROM scans 
            WHERE COALESCE(schema_version, 1) < 2
        """)
        rows = c.fetchall()
        stats["total"] = len(rows)
        
        for scan_id, scan_uuid, target, output in rows:
            try:
                with conn:  # transaction per scan
                    result = _migrate_single_scan(
                        conn, scan_id, scan_uuid, output or "", target
                    )
                    if result:
                        stats["migrated_json"] += 1
                    else:
                        stats["migrated_text"] += 1
            except Exception as e:
                logger.error(f"Failed to migrate scan {scan_uuid}: {e}")
                stats["errors"] += 1
        
        logger.info(f"Migration complete: {stats}")
        return stats
        
    finally:
        conn.close()
