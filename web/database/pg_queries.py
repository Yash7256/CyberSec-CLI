"""
PostgreSQL query helpers — mirrors web/database/queries.py interface.
Used when DATABASE_URL is set and asyncpg is available.
"""
import uuid as uuid_lib
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any


async def pg_create_scan_record(
    conn,
    target: str,
    ip: Optional[str],
    command: str,
    user_id: Optional[str] = None,
    scan_type: Optional[str] = None,
    scan_uuid: Optional[str] = None,
) -> tuple:
    """Create a scan record in PostgreSQL. Returns (scan_uuid, scan_id)."""
    scan_uuid = scan_uuid or str(uuid_lib.uuid4())
    ts = datetime.now(timezone.utc)
    row = await conn.fetchrow("""
        INSERT INTO scans (uuid, user_id, timestamp, target, ip, command,
                           scan_type, status, schema_version, output_format)
        VALUES ($1,$2,$3,$4,$5,$6,$7,'running',2,'json')
        RETURNING id
    """, scan_uuid, user_id, ts, target, ip or "", command, scan_type)
    return scan_uuid, row["id"]


async def pg_save_port_result(conn, scan_id: int, port_data: dict) -> int:
    """Save a single open port result to PostgreSQL. Returns port_id."""
    import enum
    def _to_str(v):
        if isinstance(v, enum.Enum): return str(v.name)
        return v

    port    = port_data.get("port")
    proto   = port_data.get("protocol", "tcp")
    svc     = port_data.get("service")
    ver     = port_data.get("version")
    banner  = (port_data.get("banner") or "")[:500]
    risk    = _to_str(port_data.get("risk") or "LOW")
    cvss    = float(port_data.get("cvss_score") or 0.0)
    conf    = float(port_data.get("confidence") or 0.0)
    tls     = port_data.get("tls_info") or {}
    tls_ver = tls.get("tls_version") if tls else None
    http    = port_data.get("http_info") or {}
    http_st = http.get("status_code") if http else None

    risk_map = {"critical":"CRITICAL","high":"HIGH","medium":"MEDIUM","low":"LOW",
                "CRITICAL":"CRITICAL","HIGH":"HIGH","MEDIUM":"MEDIUM","LOW":"LOW"}
    norm_risk = risk_map.get(risk, risk or "LOW")

    row = await conn.fetchrow("""
        INSERT INTO scan_ports
        (scan_id, port, protocol, service, version, banner,
         risk, cvss_score, confidence, tls_version, http_status)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
        RETURNING id
    """, scan_id, port, proto, svc, ver, banner,
         norm_risk, cvss, conf, tls_ver, http_st)
    port_id = row["id"]

    vulns = port_data.get("vulnerabilities") or []
    for cve in vulns:
        if not cve: continue
        if isinstance(cve, str):
            cve_id, cve_cvss = cve, cvss
        else:
            cve_id   = cve.get("cve_id", "")
            cve_cvss = float(cve.get("cvss_score") or cvss)
        if not cve_id: continue
        if cve_cvss >= 9.0:   sev = "CRITICAL"
        elif cve_cvss >= 7.0: sev = "HIGH"
        elif cve_cvss >= 4.0: sev = "MEDIUM"
        else:                 sev = "LOW"
        await conn.execute("""
            INSERT INTO scan_cves (port_id, scan_id, cve_id, cvss_score, severity)
            VALUES ($1,$2,$3,$4,$5)
        """, port_id, scan_id, cve_id, cve_cvss, sev)

    return port_id


async def pg_finalize_scan(
    conn, scan_id: int, status: str = "completed", raw_output: Optional[str] = None
) -> None:
    """Finalize scan — update status and rebuild scan_summary."""
    row = await conn.fetchrow("""
        SELECT
            COUNT(*)                                         AS open_port_count,
            COALESCE(MAX(cvss_score), 0.0)                  AS max_cvss_score,
            SUM(CASE WHEN risk='CRITICAL' THEN 1 ELSE 0 END) AS critical_count,
            SUM(CASE WHEN risk='HIGH'     THEN 1 ELSE 0 END) AS high_count,
            SUM(CASE WHEN risk='MEDIUM'   THEN 1 ELSE 0 END) AS medium_count,
            SUM(CASE WHEN risk='LOW'      THEN 1 ELSE 0 END) AS low_count
        FROM scan_ports WHERE scan_id = $1
    """, scan_id)

    cve_count = await conn.fetchval(
        "SELECT COUNT(*) FROM scan_cves WHERE scan_id = $1", scan_id
    )

    await conn.execute("""
        INSERT INTO scan_summary
        (scan_id, open_port_count, max_cvss_score,
         critical_count, high_count, medium_count, low_count,
         cve_count, has_cves)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
        ON CONFLICT (scan_id) DO UPDATE SET
            open_port_count = EXCLUDED.open_port_count,
            max_cvss_score  = EXCLUDED.max_cvss_score,
            critical_count  = EXCLUDED.critical_count,
            high_count      = EXCLUDED.high_count,
            medium_count    = EXCLUDED.medium_count,
            low_count       = EXCLUDED.low_count,
            cve_count       = EXCLUDED.cve_count,
            has_cves        = EXCLUDED.has_cves
    """, scan_id,
         row["open_port_count"], round(float(row["max_cvss_score"]), 2),
         row["critical_count"], row["high_count"],
         row["medium_count"],   row["low_count"],
         cve_count, 1 if cve_count > 0 else 0)

    if raw_output:
        await conn.execute(
            "UPDATE scans SET status=$1, raw_output=$2 WHERE id=$3",
            status, raw_output, scan_id
        )
    else:
        await conn.execute(
            "UPDATE scans SET status=$1 WHERE id=$2", status, scan_id
        )


async def pg_list_scans(
    conn,
    user_id: Optional[str] = None,
    limit: int = 50,
    min_cvss: Optional[float] = None,
    severity: Optional[str] = None,
    target: Optional[str] = None,
    has_cves: Optional[bool] = None,
) -> List[Dict]:
    """List scans with filters. Returns metadata + summary."""
    conditions = []
    params = []
    idx = 1

    if user_id:
        conditions.append(f"s.user_id = ${idx}"); params.append(user_id); idx+=1
    if target:
        conditions.append(f"s.target LIKE ${idx}"); params.append(f"%{target}%"); idx+=1
    if min_cvss is not None:
        conditions.append(f"ss.max_cvss_score >= ${idx}"); params.append(min_cvss); idx+=1
    if severity:
        col_map = {"CRITICAL":"ss.critical_count","HIGH":"ss.high_count",
                   "MEDIUM":"ss.medium_count","LOW":"ss.low_count"}
        col = col_map.get(severity.upper())
        if col: conditions.append(f"{col} > 0")
    if has_cves is not None:
        conditions.append(f"ss.has_cves = ${idx}"); params.append(1 if has_cves else 0); idx+=1

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    params.append(limit)

    rows = await conn.fetch(f"""  # nosec B608
        SELECT s.uuid, s.timestamp, s.target, s.ip, s.command,
               s.scan_type, s.status, s.output_format,
               ss.open_port_count, ss.max_cvss_score,
               ss.critical_count, ss.high_count,
               ss.medium_count, ss.low_count,
               ss.cve_count, ss.has_cves
        FROM scans s
        LEFT JOIN scan_summary ss ON ss.scan_id = s.id
        {where}
        ORDER BY s.id DESC LIMIT ${idx}
    """, *params)
    return [dict(r) for r in rows]


async def pg_get_scan_detail(
    conn, scan_uuid: str, user_id: Optional[str] = None
) -> Optional[Dict]:
    """Get full scan detail from PostgreSQL."""
    if user_id:
        row = await conn.fetchrow("""
            SELECT s.*, ss.*
            FROM scans s LEFT JOIN scan_summary ss ON ss.scan_id = s.id
            WHERE s.uuid = $1 AND (s.user_id = $2 OR s.user_id IS NULL)
        """, scan_uuid, user_id)
    else:
        row = await conn.fetchrow("""
            SELECT s.*, ss.*
            FROM scans s LEFT JOIN scan_summary ss ON ss.scan_id = s.id
            WHERE s.uuid = $1
        """, scan_uuid)

    if not row: return None
    scan = dict(row)
    scan_id = scan["id"]

    ports = await conn.fetch("""
        SELECT id, port, protocol, service, version, banner,
               risk, cvss_score, confidence, tls_version, http_status
        FROM scan_ports WHERE scan_id = $1
        ORDER BY cvss_score DESC, port ASC
    """, scan_id)
    ports = [dict(p) for p in ports]

    port_ids = [p["id"] for p in ports]
    cve_map = {}
    if port_ids:
        cves = await conn.fetch("""
            SELECT port_id, cve_id, cvss_score, severity
            FROM scan_cves WHERE port_id = ANY($1)
        """, port_ids)
        for c in cves:
            cve_map.setdefault(c["port_id"], []).append({
                "cve_id": c["cve_id"],
                "cvss_score": c["cvss_score"],
                "severity": c["severity"],
            })

    for p in ports:
        p["vulnerabilities"] = cve_map.get(p["id"], [])
        del p["id"]

    return {
        "uuid": scan_uuid, "target": scan["target"], "ip": scan["ip"],
        "timestamp": str(scan["timestamp"]), "scan_type": scan.get("scan_type"),
        "status": scan.get("status"),
        "summary": {
            "open_port_count":     scan.get("open_port_count", 0),
            "max_cvss_score":      scan.get("max_cvss_score", 0.0),
            "critical_count":      scan.get("critical_count", 0),
            "high_count":          scan.get("high_count", 0),
            "medium_count":        scan.get("medium_count", 0),
            "low_count":           scan.get("low_count", 0),
            "cve_count":           scan.get("cve_count", 0),
        },
        "open_ports": ports,
    }
