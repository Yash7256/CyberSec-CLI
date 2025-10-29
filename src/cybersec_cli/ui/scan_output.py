"""Module for handling scan output formatting"""
from datetime import datetime as dt
from typing import List, Dict, Any

from rich.layout import Layout
from rich.panel import Panel
from rich.text import Text
from rich.table import Table

def format_summary_panel(target: str, findings: List[Dict[str, Any]]) -> Panel:
    """Create a summary panel with enhanced scan results"""
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    total_risk_score = 0
    
    for f in findings:
        severity = f.get("severity", "Info")
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Calculate weighted risk score (CVSS score * confidence)
        cvss_score = f.get("cvss", {}).get("score", 0)
        confidence = f.get("confidence", 0.5)  # Default to 0.5 if not specified
        total_risk_score += cvss_score * confidence
    
    # Calculate average risk score
    avg_risk_score = total_risk_score / len(findings) if findings else 0
    
    # Determine overall risk level
    if avg_risk_score >= 7.0:
        risk_level = "[red]Critical[/]"
    elif avg_risk_score >= 4.0:
        risk_level = "[yellow]High[/]"
    elif avg_risk_score > 0:
        risk_level = "[cyan]Medium[/]"
    else:
        risk_level = "[green]Low[/]"
    
    # Format findings summary with color coding
    findings_summary = (
        f"[red]🔴 {severity_counts.get('Critical', 0)} Critical[/], "
        f"[red]🟠 {severity_counts.get('High', 0)} High[/], "
        f"[yellow]🟡 {severity_counts.get('Medium', 0)} Medium[/], "
        f"[cyan]🔵 {severity_counts.get('Low', 0)} Low[/], "
        f"[dim]⚪ {severity_counts.get('Info', 0)} Info[/]"
    )
    
    # Add risk score to summary
    risk_score_text = (
        f"[bold]Risk Score:[/] {avg_risk_score:.1f}/10.0 ({risk_level})\n"
        f"[dim]Based on {len(findings)} findings"
    )
    
    # Create a grid layout for the summary panel
    summary_grid = Table.grid(padding=(0, 1))
    
    # Add target and timestamp
    summary_grid.add_row("🎯 [bold]Target:[/]", target)
    summary_grid.add_row("🕒 [bold]Timestamp:[/]", dt.now().strftime('%Y-%m-%d %H:%M:%S'))
    
    # Add findings summary with severity breakdown
    findings_table = Table.grid(padding=(0, 2))
    findings_table.add_row("📊 [bold]Findings:[/]", findings_summary)
    summary_grid.add_row("", "")  # Add spacing
    summary_grid.add_row(findings_table)
    
    # Add risk score
    summary_grid.add_row("", "")  # Add spacing
    summary_grid.add_row(Text.from_markup(risk_score_text))
    
    return Panel(
        summary_grid,
        title="[bold]🔍 Scan Summary[/]",
        border_style="blue",
        expand=False,
        padding=(1, 2)
    )

def format_finding_panel(finding: Dict[str, Any]) -> Panel:
    """Create a panel for an individual finding with enhanced risk scoring"""
    severity = finding["severity"]
    color = {"Critical": "red", "High": "red", "Medium": "yellow", "Low": "cyan"}.get(severity, "dim")
    
    # Format CVSS information
    cvss = finding.get("cvss", {})
    cvss_score = cvss.get("score", 0)
    cvss_vector = cvss.get("vector", "N/A")
    
    # Format exploitability information
    exploitability = finding.get("exploitability", {})
    
    # Create risk assessment table
    risk_table = Table.grid(padding=(0, 2))
    
    # CVSS Score with color coding
    cvss_color = "red" if cvss_score >= 7.0 else "yellow" if cvss_score >= 4.0 else "green"
    risk_table.add_row("📊 [bold]CVSS Score:[/]", f"[{cvss_color}]{cvss_score:.1f} ({cvss.get('severity', 'N/A')})[/]")
    
    # CVSS Vector
    risk_table.add_row("🎯 [bold]CVSS Vector:[/]", f"[dim]{cvss_vector}")
    
    # Exploitability Metrics
    risk_table.add_row("🔍 [bold]Exploit Maturity:[/]", 
                      f"{exploitability.get('maturity', 'Unknown')} "
                      f"({'🔴' if exploitability.get('public_exploits') else '🟢'})")
    
    # Confidence Level
    confidence = finding.get("confidence", 0) * 100
    confidence_color = "green" if confidence >= 80 else "yellow" if confidence >= 50 else "red"
    risk_table.add_row("🎯 [bold]Confidence:[/]", 
                      f"[{confidence_color}]{confidence:.0f}%" + 
                      (" (High)" if confidence >= 80 else " (Medium)" if confidence >= 50 else " (Low)") + "[/]")
    
    # CWE and Compliance
    risk_table.add_row("📋 [bold]CWE ID:[/]", finding.get("cwe_id", "N/A"))
    
    # Format MITRE ATT&CK TTPs
    mitre_attack = finding.get("mitre_attack", [])
    if mitre_attack:
        risk_table.add_row("🎯 [bold]MITRE ATT&CK:[/]", 
                         ", ".join([f"[cyan]{t}[/]" for t in mitre_attack]))
    
    # Format compliance information
    compliance = finding.get("compliance", [])
    if compliance:
        if isinstance(compliance, list):
            compliance_str = "\n    ".join(compliance)
        else:
            compliance_str = str(compliance)
        risk_table.add_row("📜 [bold]Compliance:[/]", f"[dim]{compliance_str}")
    
    # Format content with enhanced details
    finding_content = [
        f'📄 [bold]Finding:[/] {finding["finding"]} [dim](Port {finding["port"]})[/]',
        "-" * 80,
        f'🔬 [bold]Details:[/] {finding["details"]}',
        "",
        f'⚠️  [bold]Risk Impact:[/]',
        finding.get("impact", "Potential security vulnerability that could lead to unauthorized access or data exposure."),
        "",
        f'📊 [bold]Risk Assessment[/]',
        str(risk_table),
        "",
        f'🛡️  [bold]Recommendations:[/]',
        finding.get("recommendation", "No specific recommendations available."),
        ""
    ]
    
    return Panel(
        Text.from_markup("\n".join(finding_content)),
        title=f"[bold]Port {finding['port']} - [{color}]{severity}[/][/]",
        border_style=color,
        expand=False
    )

def format_recommendations(findings: List[Dict[str, Any]]) -> Panel:
    """Create recommendations panel with prioritized actions"""
    # Group findings by severity
    findings_by_severity = {
        "High": [],
        "Medium": [],
        "Low": []
    }
    
    for finding in findings:
        severity = finding["severity"]
        if severity in findings_by_severity:
            findings_by_severity[severity].append(finding)
    
    # Create recommendations text
    actions_text = "[bold]🔧 Recommended Actions (By Priority)[/]\n\n"
    
    severity_info = {
        "High": ("🔴", "red", "Critical"),
        "Medium": ("🟠", "yellow", "Medium Severity"),
        "Low": ("🟢", "green", "Low Severity")
    }
    
    for severity, (emoji, color, label) in severity_info.items():
        if findings_by_severity[severity]:
            actions_text += f"[bold {color}]{emoji} {label}[/]\n\n"
            for finding in findings_by_severity[severity]:
                actions_text += f"[bold]{finding['finding']}[/]\n"
                recommendations = finding.get('recommendation', '').split('\n')
                recommendations = [r.strip() for r in recommendations if r.strip()]
                recommendations = [r.replace('1. ', '• ') if r.startswith('1. ') else f"• {r}" 
                                 for r in recommendations]
                actions_text += "\n".join(recommendations) + "\n\n"
    
    # Add scope section
    actions_text += "[bold]🧠 Scope of Recommendations[/]\n\n"
    actions_text += (
        "This scan suggests that the target (or its hosting environment) "
        "may have security configurations that need attention.\n"
        "Your remediation scope should include:\n\n"
        "🔒 [bold]Network-level security:[/] Firewall rules, service exposure reduction\n"
        "🖥️ [bold]System hardening:[/] Service configurations, authentication methods\n"
        "🌐 [bold]Web security:[/] Protocol enforcement, TLS configuration\n"
        "📊 [bold]Ongoing monitoring:[/] Regular vulnerability scans + intrusion detection\n"
    )
    
    return Panel(
        Text.from_markup(actions_text),
        title="[bold]Recommended Actions & Scope[/]",
        border_style="blue",
        expand=False
    )

def create_scan_output(target: str, findings: List[Dict[str, Any]]) -> Layout:
    """Create a complete layout for scan results"""
    output_layout = Layout()
    
    # Create all panels
    summary_panel = format_summary_panel(target, findings)
    recommendations_panel = format_recommendations(findings)
    
    # Sort findings by severity
    severity_order = {"High": 1, "Medium": 2, "Low": 3, "Info": 4}
    sorted_findings = sorted(findings, key=lambda x: severity_order.get(x["severity"], 5))
    finding_panels = [format_finding_panel(finding) for finding in sorted_findings]
    
    # Combine all panels
    panels = [summary_panel, recommendations_panel] + finding_panels
    output_layout.split_column(*panels)
    
    return output_layout