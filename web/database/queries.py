"""
Normalized query helpers — replaces raw SQL in web/main.py
All functions return dicts, not sqlite3.Row objects.
"""

import sqlite3
from typing import Optional, List, Dict, Any


def list_scans(
    conn: sqlite3.Connection,
    user_id: Optional[str] = None,
    limit: int = 50,
    min_cvss: Optional[float] = None,
    severity: Optional[str] = None,
    target: Optional[str] = None,
    has_cves: Optional[bool] = None,
) -> List[Dict]:
    """
    List scans with optional filters. Returns metadata + summary.
    No output blob loaded — fast even with thousands of scans.
    """
    conditions = []
    params = []
    
    if user_id:
        conditions.append("s.user_id = ?")
        params.append(user_id)
    
    if target:
        conditions.append("s.target LIKE ?")
        params.append(f"%{target}%")
    
    if min_cvss is not None:
        conditions.append("ss.max_cvss_score >= ?")
        params.append(min_cvss)
    
    if severity:
        col_map = {
            "CRITICAL": "ss.critical_count",
            "HIGH": "ss.high_count",
            "MEDIUM": "ss.medium_count",
            "LOW": "ss.low_count",
        }
        col = col_map.get(severity.upper())
        if col:
            conditions.append(f"{col} > 0")
    
    if has_cves is not None:
        conditions.append("ss.has_cves = ?")
        params.append(1 if has_cves else 0)
    
    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    params.append(limit)
    
    query = f"""
        SELECT 
            s.uuid, s.timestamp, s.target, s.ip, s.command,
            s.scan_type, s.status, s.output_format,
            ss.open_port_count, ss.max_cvss_score,
            ss.critical_count, ss.high_count,
            ss.medium_count, ss.low_count,
            ss.cve_count, ss.has_cves
        FROM scans s
        LEFT JOIN scan_summary ss ON ss.scan_id = s.id
        {where}
        ORDER BY s.id DESC
        LIMIT ?
    """
    
    c = conn.cursor()
    c.execute(query, params)
    cols = [d[0] for d in c.description]
    return [dict(zip(cols, row)) for row in c.fetchall()]


def get_scan_detail(
    conn: sqlite3.Connection,
    scan_uuid: str,
    user_id: Optional[str] = None,
) -> Optional[Dict]:
    """
    Get full scan detail including ports and CVEs.
    Does NOT load raw_output blob — reconstructs from normalized tables.
    """
    c = conn.cursor()
    
    # Get scan + summary
    if user_id:
        c.execute("""
            SELECT s.*, ss.*
            FROM scans s
            LEFT JOIN scan_summary ss ON ss.scan_id = s.id
            WHERE s.uuid = ? AND (s.user_id = ? OR s.user_id IS NULL)
        """, (scan_uuid, user_id))
    else:
        c.execute("""
            SELECT s.*, ss.*
            FROM scans s
            LEFT JOIN scan_summary ss ON ss.scan_id = s.id
            WHERE s.uuid = ?
        """, (scan_uuid,))
    
    row = c.fetchone()
    if not row:
        return None
    
    cols = [d[0] for d in c.description]
    scan = dict(zip(cols, row))
    scan_id = scan["id"]
    
    # For text-format scans, return raw_output directly
    if scan.get("output_format") == "text":
        return {"uuid": scan_uuid, "output": scan.get("raw_output", "")}
    
    # Get ports
    c.execute("""
        SELECT id, port, protocol, service, version, banner,
               risk, cvss_score, confidence, tls_version, http_status
        FROM scan_ports
        WHERE scan_id = ?
        ORDER BY cvss_score DESC, port ASC
    """, (scan_id,))
    port_cols = [d[0] for d in c.description]
    ports = [dict(zip(port_cols, r)) for r in c.fetchall()]
    
    # Get CVEs per port
    port_ids = [p["id"] for p in ports]
    cve_map = {}
    if port_ids:
        placeholders = ",".join("?" * len(port_ids))
        c.execute(f"""
            SELECT port_id, cve_id, cvss_score, severity
            FROM scan_cves
            WHERE port_id IN ({placeholders})
        """, port_ids)
        for row in c.fetchall():
            pid, cve_id, cvss, sev = row
            cve_map.setdefault(pid, []).append({
                "cve_id": cve_id,
                "cvss_score": cvss,
                "severity": sev,
            })
    
    # Attach CVEs to ports
    for port in ports:
        port["vulnerabilities"] = cve_map.get(port["id"], [])
        del port["id"]  # Internal ID not needed in response
    
    return {
        "uuid":     scan_uuid,
        "target":   scan["target"],
        "ip":       scan["ip"],
        "timestamp": scan["timestamp"],
        "scan_type": scan.get("scan_type"),
        "status":   scan.get("status"),
        "summary": {
            "open_port_count":     scan.get("open_port_count", 0),
            "max_cvss_score":      scan.get("max_cvss_score", 0.0),
            "critical_count":      scan.get("critical_count", 0),
            "high_count":          scan.get("high_count", 0),
            "medium_count":        scan.get("medium_count", 0),
            "low_count":           scan.get("low_count", 0),
            "cve_count":           scan.get("cve_count", 0),
            "total_ports_scanned": scan.get("total_ports_scanned", 0),
        },
        "open_ports": ports,
    }


def get_scan_stats(conn: sqlite3.Connection, user_id: Optional[str] = None) -> Dict:
    """
    Aggregate statistics across all scans.
    Useful for dashboard summary widgets.
    """
    c = conn.cursor()
    where = "WHERE s.user_id = ?" if user_id else ""
    params = [user_id] if user_id else []
    
    c.execute(f"""
        SELECT
            COUNT(DISTINCT s.id)            AS total_scans,
            SUM(ss.open_port_count)         AS total_open_ports,
            SUM(ss.cve_count)               AS total_cves,
            SUM(ss.critical_count)          AS total_critical,
            MAX(ss.max_cvss_score)          AS highest_cvss,
            COUNT(DISTINCT s.target)        AS unique_targets
        FROM scans s
        LEFT JOIN scan_summary ss ON ss.scan_id = s.id
        {where}
    """, params)
    
    cols = [d[0] for d in c.description]
    row = c.fetchone()
    return dict(zip(cols, row)) if row else {}


def _insert_normalized_data(conn, scan_id: int, output: str):
    """Called after every new scan save to populate normalized tables."""
    from web.database.migrate import _migrate_single_scan
    try:
        _migrate_single_scan(conn, scan_id, "", output, "")
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(
            f"Failed to normalize scan {scan_id}: {e}"
        )


def create_scan_record(
    db_path: str,
    target: str,
    ip: Optional[str],
    command: str,
    user_id: Optional[str] = None,
    scan_type: Optional[str] = None,
) -> tuple:
    """
    Create a placeholder scan row at scan START.
    Returns (scan_uuid, scan_id).
    Status is 'running' until finalized.
    """
    import uuid as uuid_lib
    from datetime import datetime
    
    scan_uuid = str(uuid_lib.uuid4())
    ts = datetime.utcnow().isoformat() + "Z"
    
    with sqlite3.connect(db_path) as conn:
        c = conn.cursor()
        c.execute("""
            INSERT INTO scans 
            (uuid, user_id, timestamp, target, ip, command, 
             scan_type, status, schema_version, output_format)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'running', 2, 'json')
        """, (scan_uuid, user_id, ts, target, ip or "", 
              command, scan_type))
        scan_id = c.lastrowid
        conn.commit()
    
    return scan_uuid, scan_id


def save_port_result(
    db_path: str,
    scan_id: int,
    port_data: dict,
) -> int:
    """
    Save a single open port result immediately when discovered.
    Returns port_id (scan_ports.id).
    Called once per open port during scanning.
    
    port_data keys (all optional except port):
        port, protocol, service, version, banner,
        risk, cvss_score, confidence,
        tls_info (dict), http_info (dict),
        vulnerabilities (list of str or dict)
    """
    import enum
    port   = port_data.get("port")
    proto  = port_data.get("protocol", "tcp")
    svc    = port_data.get("service")
    ver    = port_data.get("version")
    banner = (port_data.get("banner") or "")[:500]
    risk_raw = port_data.get("risk") or port_data.get("severity", "")
    # Convert Enum to string if needed (Severity Enum leaks from formatters.py)
    # Check .name first (for Enums like Severity.LOW -> "LOW")
    if isinstance(risk_raw, enum.Enum):
        risk = str(risk_raw.name)
    elif hasattr(risk_raw, 'name') and hasattr(risk_raw, 'value'):
        # This is an Enum, use .name
        risk = str(risk_raw.name)
    elif hasattr(risk_raw, 'value'):
        risk = str(risk_raw.value)
    else:
        risk = str(risk_raw) if risk_raw else ""
    cvss   = float(port_data.get("cvss_score") or 0.0)
    conf   = float(port_data.get("confidence") or 0.0)
    
    tls    = port_data.get("tls_info") or {}
    tls_ver = tls.get("tls_version") if tls else None
    
    http   = port_data.get("http_info") or {}
    http_st = http.get("status_code") if http else None
    
    risk_map = {
        "critical": "CRITICAL", "high": "HIGH",
        "medium": "MEDIUM",     "low": "LOW",
        "CRITICAL": "CRITICAL", "HIGH": "HIGH",
        "MEDIUM": "MEDIUM",     "LOW": "LOW",
    }
    norm_risk = risk_map.get(risk, risk or "LOW")
    
    with sqlite3.connect(db_path) as conn:
        c = conn.cursor()
        
        c.execute("""
            INSERT INTO scan_ports
            (scan_id, port, protocol, service, version, banner,
             risk, cvss_score, confidence, tls_version, http_status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (scan_id, port, proto, svc, ver, banner,
              norm_risk, cvss, conf, tls_ver, http_st))
        port_id = c.lastrowid
        
        vulns = port_data.get("vulnerabilities") or []
        for cve in vulns:
            if not cve:
                continue
            if isinstance(cve, str):
                cve_id   = cve
                cve_cvss = cvss
            else:
                cve_id   = cve.get("cve_id", "")
                cve_cvss = float(cve.get("cvss_score") or cvss)
            
            if not cve_id:
                continue
            
            if cve_cvss >= 9.0:   sev = "CRITICAL"
            elif cve_cvss >= 7.0: sev = "HIGH"
            elif cve_cvss >= 4.0: sev = "MEDIUM"
            else:                 sev = "LOW"
            
            c.execute("""
                INSERT INTO scan_cves 
                (port_id, scan_id, cve_id, cvss_score, severity)
                VALUES (?, ?, ?, ?, ?)
            """, (port_id, scan_id, cve_id, cve_cvss, sev))
        
        conn.commit()
    
    return port_id


def finalize_scan(
    db_path: str,
    scan_id: int,
    status: str = "completed",
    raw_output: Optional[str] = None,
) -> None:
    """
    Called at scan END (success or failure).
    - Updates scan status
    - Saves raw_output if provided
    - Rebuilds scan_summary from actual scan_ports rows
    """
    with sqlite3.connect(db_path) as conn:
        c = conn.cursor()
        
        c.execute("""
            SELECT
                COUNT(*)                                    AS open_port_count,
                COALESCE(MAX(cvss_score), 0.0)             AS max_cvss_score,
                SUM(CASE WHEN risk='CRITICAL' THEN 1 ELSE 0 END) AS critical_count,
                SUM(CASE WHEN risk='HIGH'     THEN 1 ELSE 0 END) AS high_count,
                SUM(CASE WHEN risk='MEDIUM'   THEN 1 ELSE 0 END) AS medium_count,
                SUM(CASE WHEN risk='LOW'      THEN 1 ELSE 0 END) AS low_count
            FROM scan_ports WHERE scan_id = ?
        """, (scan_id,))
        row = c.fetchone()
        open_count, max_cvss, crit, high, med, low = row
        
        c.execute("""
            SELECT COUNT(*) FROM scan_cves WHERE scan_id = ?
        """, (scan_id,))
        cve_count = c.fetchone()[0]
        
        c.execute("""
            INSERT OR REPLACE INTO scan_summary
            (scan_id, open_port_count, max_cvss_score,
             critical_count, high_count, medium_count, low_count,
             cve_count, has_cves)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (scan_id, open_count, round(max_cvss, 2),
              crit, high, med, low,
              cve_count, 1 if cve_count > 0 else 0))
        
        if raw_output:
            c.execute("""
                UPDATE scans 
                SET status = ?, raw_output = ?
                WHERE id = ?
            """, (status, raw_output, scan_id))
        else:
            c.execute("""
                UPDATE scans SET status = ? WHERE id = ?
            """, (status, scan_id))
        
        conn.commit()
