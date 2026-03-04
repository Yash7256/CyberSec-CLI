import json
from typing import Optional
from web.utils.token_utils import TokenCounter, get_context_token_budget


def summarize_scan_context(raw_context: str, model: str) -> str:
    budget = get_context_token_budget(model)
    current_tokens = TokenCounter.count(raw_context)
    
    if current_tokens <= budget:
        return raw_context
    
    parsed = _try_parse_context(raw_context)
    if parsed is None:
        return _truncate_text_smartly(raw_context, budget)
    
    return _build_structured_summary(parsed, budget)


def _try_parse_context(raw: str) -> Optional[dict]:
    clean = raw.replace("=== COMPLETE SCAN RESULTS ===\n", "")
    clean = clean.replace("=== SCAN RESULTS (from UI) ===\n", "")
    try:
        return json.loads(clean)
    except json.JSONDecodeError:
        return None


def _build_structured_summary(data: dict, budget: int) -> str:
    lines = ["## Scan Summary (AI-Optimized Context)"]
    
    target = data.get("target") or data.get("ip", "unknown")
    scan_type = data.get("scan_type", "unknown")
    timestamp = data.get("timestamp", "")
    
    lines += [
        f"- **Target:** {target}",
        f"- **Scan Type:** {scan_type}",
        f"- **Timestamp:** {timestamp}",
        "",
    ]
    
    all_open = _extract_all_open_ports(data)
    lines.append(f"- **Total Open Ports Found:** {len(all_open)}")
    lines.append("")
    
    critical_ports = _get_by_severity(data, ["critical", "CRITICAL"])
    high_ports = _get_by_severity(data, ["high", "HIGH", "High"])
    
    if critical_ports:
        lines.append("## 🔴 Critical Severity Ports")
        for p in critical_ports:
            lines.append(_format_port_line(p))
        lines.append("")
    
    if high_ports:
        lines.append("## 🟠 High Severity Ports")
        for p in high_ports:
            lines.append(_format_port_line(p))
        lines.append("")
    
    current = "\n".join(lines)
    remaining_budget = budget - TokenCounter.count(current) - 200
    
    top_cves = _extract_top_cves(all_open, limit=5)
    if top_cves and remaining_budget > 200:
        cve_lines = ["## Top Vulnerabilities (by CVSS Score)"]
        for cve in top_cves:
            cve_lines.append(
                f"- **{cve['id']}** | CVSS {cve['cvss']} | "
                f"Port {cve['port']} ({cve['service']})"
            )
        cve_lines.append("")
        cve_text = "\n".join(cve_lines)
        if TokenCounter.count(cve_text) < remaining_budget:
            lines += cve_lines
            remaining_budget -= TokenCounter.count(cve_text)
    
    medium_ports = _get_by_severity(data, ["medium", "MEDIUM", "Medium"])
    if medium_ports and remaining_budget > 300:
        med_lines = ["## 🟡 Medium Severity Ports"]
        for p in medium_ports[:10]:
            med_lines.append(_format_port_line(p))
        med_text = "\n".join(med_lines)
        if TokenCounter.count(med_text) < remaining_budget:
            lines += med_lines
    
    lines += [
        "",
        f"*Note: Context summarized from {len(all_open)} open ports "
        f"to fit AI token budget. Full results available in scan history.*"
    ]
    
    return "\n".join(lines)


def _format_port_line(port: dict) -> str:
    p = port.get("port", "?")
    svc = port.get("service", "unknown")
    ver = port.get("version", "")
    vulns = port.get("vulnerabilities", [])
    cvss = port.get("cvss_score", "")
    
    vuln_str = f" | CVEs: {', '.join(vulns[:2])}" if vulns else ""
    cvss_str = f" | CVSS: {cvss}" if cvss else ""
    ver_str = f" {ver}" if ver else ""
    
    return f"- Port **{p}**: {svc}{ver_str}{cvss_str}{vuln_str}"


def _extract_all_open_ports(data: dict) -> list:
    if "results" in data:
        return [r for r in data["results"] if r.get("state") == "open"]
    all_ports = []
    for level in ["critical", "high", "medium", "low"]:
        all_ports.extend(data.get(level, []))
    return all_ports


def _get_by_severity(data: dict, keys: list) -> list:
    for key in keys:
        if key in data:
            return data[key]
    return []


def _extract_top_cves(ports: list, limit: int = 5) -> list:
    cves = []
    for port in ports:
        for cve_id in port.get("vulnerabilities", []):
            cves.append({
                "id": cve_id,
                "cvss": port.get("cvss_score", 0),
                "port": port.get("port"),
                "service": port.get("service", "unknown"),
            })
    return sorted(cves, key=lambda x: x["cvss"], reverse=True)[:limit]


def _truncate_text_smartly(text: str, budget: int) -> str:
    target_chars = budget * 3
    truncated = text[:target_chars]
    last_newline = truncated.rfind('\n')
    if last_newline > target_chars * 0.7:
        truncated = truncated[:last_newline]
    return truncated + "\n\n[Summary truncated — use full scan view for complete data]"
