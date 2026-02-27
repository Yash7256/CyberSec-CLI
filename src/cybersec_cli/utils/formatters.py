"""Output formatters for Cybersec CLI."""

import logging
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from rich import box
from rich.console import Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from cybersec_cli.tools.network import PortResult, PortScanner, PortState

logger = logging.getLogger(__name__)

class Severity(Enum):
    """Severity levels for security findings."""

    CRITICAL = ("Critical", "bold red")
    HIGH = ("High", "red")
    MEDIUM = ("Medium", "yellow")
    LOW = ("Low", "blue")
    INFO = ("Info", "cyan")

    def __init__(self, display_name: str, style: str):
        self.display_name = display_name
        self.style = style


def _get_severity_style(severity: Severity, default: str = "blue") -> str:
    """Safely extract a style string from the Severity tuple."""
    value = severity.value
    if len(value) >= 2:
        return value[1]
    logger.warning("Unexpected severity tuple length: %s", len(value))
    return default


# Common vulnerabilities by port and service with detailed information
VULNERABILITY_DB = {
    # FTP (File Transfer Protocol)
    21: {
        "severity": Severity.HIGH,
        "description": "FTP service detected",
        "recommendation": (
            "1. Use SFTP or FTPS instead of plain FTP\n"
            "2. If FTP is required:\n"
            "   - Enable TLS encryption\n"
            "   - Use strong authentication\n"
            "   - Implement IP restrictions\n"
            "   - Enable logging and monitoring\n"
            "   - Use passive mode with a limited port range"
        ),
        "cvss_score": 7.5,
        "cves": ["CVE-2020-15778", "CVE-2019-18277"],
        "exposure": "Internet/Internal",
        "default_creds": "Common (admin:admin, ftp:ftp, anonymous:anonymous)",
        "mitre_attack": ["T1040", "T1078"],
    },
    # HTTP alternate port
    81: {
        "severity": Severity.MEDIUM,
        "description": "HTTP service detected (alt port)",
        "recommendation": (
            "1. Enforce HTTPS and redirect HTTP on this port\n"
            "2. Apply the same hardening as port 80 (HSTS, headers)\n"
            "3. Disable if not strictly required\n"
            "4. Restrict exposure to trusted networks"
        ),
        "cvss_score": 6.5,
        "cves": [],
        "exposure": "Internet/Internal",
        "default_creds": "Varies by application",
        "mitre_attack": ["T1071", "T1568"],
    },
    # SSH (Secure Shell)
    22: {
        "severity": Severity.MEDIUM,
        "description": "SSH service detected",
        "recommendation": (
            "1. Disable root login\n"
            "2. Use key-based authentication\n"
            "3. Disable password authentication\n"
            "4. Use strong ciphers and key exchange algorithms\n"
            "5. Implement fail2ban or similar protection\n"
            "6. Restrict access with AllowUsers/AllowGroups"
        ),
        "cvss_score": 5.3,
        "cves": ["CVE-2023-48795", "CVE-2023-38408"],
        "exposure": "Internet/Internal",
        "default_creds": "Varies by system",
        "mitre_attack": ["T1110", "T1078"],
    },
    # Telnet
    23: {
        "severity": Severity.HIGH,
        "description": "Telnet service detected",
        "recommendation": (
            "1. Disable Telnet; replace with SSH wherever possible\n"
            "2. If required temporarily, restrict access with ACLs\n"
            "3. Enforce strong authentication and monitor sessions\n"
            "4. Move sensitive services behind a VPN or jump host"
        ),
        "cvss_score": 8.0,
        "cves": [],
        "exposure": "Internet/Internal",
        "default_creds": "Varies by device; often unset",
        "mitre_attack": ["T1040", "T1078"],
    },
    # SunRPC / portmapper
    111: {
        "severity": Severity.MEDIUM,
        "description": "rpcbind/portmap exposed",
        "recommendation": (
            "1. Restrict rpcbind to internal networks\n"
            "2. Disable NFS/portmap if unused\n"
            "3. Use firewalls to limit RPC services\n"
            "4. Audit exported RPC services regularly"
        ),
        "cvss_score": 6.5,
        "cves": [],
        "exposure": "Internal recommended",
        "default_creds": "Not applicable",
        "mitre_attack": ["T1021", "T1569"],
    },
    # MySQL Database
    3306: {
        "severity": Severity.HIGH,
        "description": "MySQL database detected",
        "recommendation": (
            "1. Do not expose MySQL to untrusted networks\n"
            "2. Use strong passwords and authentication\n"
            "3. Enable TLS encryption\n"
            "4. Apply the latest security patches\n"
            "5. Restrict database user privileges\n"
            "6. Enable query logging and monitoring"
        ),
        "cvss_score": 8.8,
        "cves": ["CVE-2023-21912", "CVE-2022-21549"],
        "exposure": "Internal recommended",
        "default_creds": "root:<empty>, root:root, mysql:mysql",
        "mitre_attack": ["T1213", "T1078"],
    },
    # HTTP (Web Server)
    80: {
        "severity": Severity.MEDIUM,
        "description": "HTTP web server detected",
        "recommendation": (
            "1. Redirect HTTP to HTTPS\n"
            "2. Enable HSTS\n"
            "3. Disable directory listing\n"
            "4. Remove server version information\n"
            "5. Implement security headers (CSP, X-Content-Type, etc.)\n"
            "6. Keep server software updated"
        ),
        "cvss_score": 6.5,
        "cves": ["CVE-2023-25690", "CVE-2023-27522"],
        "exposure": "Internet/Internal",
        "default_creds": "Varies by application",
        "mitre_attack": ["T1078", "T1568"],
    },
    # HTTPS (Web Server)
    443: {
        "severity": Severity.LOW,
        "description": "HTTPS service detected",
        "recommendation": (
            "1. Enforce modern TLS (1.2+) and strong cipher suites\n"
            "2. Enable HSTS and redirect HTTP to HTTPS\n"
            "3. Monitor certificate validity and use CAA records\n"
            "4. Disable weak protocols and renegotiation issues"
        ),
        "cvss_score": 3.5,
        "cves": [],
        "exposure": "Internet/Internal",
        "default_creds": "Varies by application",
        "mitre_attack": ["T1078", "T1568"],
    },
    # HTTPS (alt ports)
    443: {
        "severity": Severity.LOW,
        "description": "HTTPS service detected",
        "recommendation": (
            "1. Enforce modern TLS (1.2+) and strong cipher suites\n"
            "2. Enable HSTS and redirect HTTP to HTTPS\n"
            "3. Monitor certificate validity and use CAA records\n"
            "4. Disable weak protocols and renegotiation issues"
        ),
        "cvss_score": 3.5,
        "cves": [],
        "exposure": "Internet/Internal",
        "default_creds": "Varies by application",
        "mitre_attack": ["T1078", "T1568"],
    },
    444: {
        "severity": Severity.LOW,
        "description": "HTTPS service detected (alt port)",
        "recommendation": (
            "1. Apply same TLS hardening as port 443\n"
            "2. Avoid exposing alternate HTTPS unless required\n"
            "3. Ensure valid certificates cover this port\n"
            "4. Redirect to primary HTTPS where possible"
        ),
        "cvss_score": 3.5,
        "cves": [],
        "exposure": "Internet/Internal",
        "default_creds": "Varies by application",
        "mitre_attack": ["T1078", "T1568"],
    },
    # SMTP submission / SMTPS
    465: {
        "severity": Severity.MEDIUM,
        "description": "SMTP submission (SMTPS) detected",
        "recommendation": (
            "1. Require authentication and enforce TLS\n"
            "2. Disable weak ciphers and SSLv2/3\n"
            "3. Enable SPF/DKIM/DMARC\n"
            "4. Rate-limit login attempts"
        ),
        "cvss_score": 6.0,
        "cves": [],
        "exposure": "Internet/Internal",
        "default_creds": "Mailbox credentials",
        "mitre_attack": ["T1586", "T1114"],
    },
    587: {
        "severity": Severity.MEDIUM,
        "description": "SMTP submission detected",
        "recommendation": (
            "1. Enforce STARTTLS and strong auth\n"
            "2. Restrict relaying; require auth\n"
            "3. Apply abuse rate limits and logging\n"
            "4. Implement SPF/DKIM/DMARC"
        ),
        "cvss_score": 6.0,
        "cves": [],
        "exposure": "Internet/Internal",
        "default_creds": "Mailbox credentials",
        "mitre_attack": ["T1586", "T1114"],
    },
    # IMAPS / POP3S
    993: {
        "severity": Severity.MEDIUM,
        "description": "IMAPS service detected",
        "recommendation": (
            "1. Enforce strong TLS and modern ciphers\n"
            "2. Disable plaintext auth (LOGIN/PLAIN without TLS)\n"
            "3. Enable MFA where possible\n"
            "4. Monitor for brute-force attempts"
        ),
        "cvss_score": 6.0,
        "cves": [],
        "exposure": "Internet/Internal",
        "default_creds": "Mailbox credentials",
        "mitre_attack": ["T1114", "T1586"],
    },
    995: {
        "severity": Severity.MEDIUM,
        "description": "POP3S service detected",
        "recommendation": (
            "1. Enforce TLS and disable plaintext auth\n"
            "2. Enable MFA where possible\n"
            "3. Rate-limit login attempts\n"
            "4. Prefer IMAP/SMTP with stronger controls"
        ),
        "cvss_score": 6.0,
        "cves": [],
        "exposure": "Internet/Internal",
        "default_creds": "Mailbox credentials",
        "mitre_attack": ["T1114", "T1586"],
    },
    # DNS (Domain Name System)
    53: {
        "severity": Severity.LOW,
        "description": "DNS service detected",
        "recommendation": (
            "1. Disable recursive queries if not needed\n"
            "2. Implement DNSSEC\n"
            "3. Restrict zone transfers\n"
            "4. Enable query logging\n"
            "5. Keep DNS software updated\n"
            "6. Consider using DoH/DoT for client queries"
        ),
        "cvss_score": 4.0,
        "cves": ["CVE-2023-2828", "CVE-2023-2829"],
        "exposure": "Internet/Internal",
        "default_creds": "Varies by implementation",
        "mitre_attack": ["T1078", "T1568"],
    },
    # Default for unknown services
    "default": {
        "severity": Severity.INFO,
        "description": "Service detected",
        "recommendation": (
            "1. Verify this service is required\n"
            "2. Restrict access to trusted networks\n"
            "3. Use strong authentication\n"
            "4. Enable encryption if available\n"
            "5. Keep software updated\n"
            "6. Monitor for suspicious activity"
        ),
        "cvss_score": 0.0,
        "cves": [],
        "exposure": "Unknown",
        "default_creds": "Check documentation",
        "mitre_attack": [],
    },
}


def get_vulnerability_info(port: int, service: Optional[str] = None) -> Dict[str, Any]:
    """Get vulnerability information for a given port.

    Args:
        port: Port number
        service: Optional service name for more specific lookup
    Returns:
        Dictionary with vulnerability information
    """
    # First try exact port match
    if port in VULNERABILITY_DB:
        return VULNERABILITY_DB[port]

    # Default to generic info
    return VULNERABILITY_DB["default"]


def format_scan_results(
    scanner: PortScanner,
    format_type: str = "table",
    show_findings: bool = True,
    show_banner: bool = True,
) -> str:
    """Format port scan results in the specified format.

    Args:
        scanner: PortScanner instance with scan results
        format_type: Output format (table, json, list)
        show_findings: Whether to include security findings
        show_banner: Whether to show the scan banner

    Returns:
        Formatted results as a string or Rich renderable
    """
    if format_type == "json":
        return scanner.to_json()

    if format_type == "list":
        return format_scan_results_list(scanner.results)

    # For table format, return a Group with banner and results
    output = []

    if show_banner:
        output.append(create_scan_banner(scanner))

    output.append(format_scan_results_table(scanner))

    if show_findings:
        findings = generate_security_findings(scanner)
        if findings:
            output.extend(findings)

    return Group(*output) if len(output) > 1 else output[0]


def create_scan_banner(scanner: PortScanner) -> Panel:
    """Create a banner panel for the scan results.

    Args:
        scanner: PortScanner instance with scan results

    Returns:
        A rich Panel with scan banner
    """
    # Get scan statistics
    open_ports = [r for r in scanner.results if r.state == PortState.OPEN]
    total_ports = len(scanner.ports)
    open_count = len(open_ports)
    closed_count = len([r for r in scanner.results if r.state == PortState.CLOSED])
    filtered_count = len([r for r in scanner.results if r.state == PortState.FILTERED])

    # Create banner content
    banner_text = Text()
    banner_text.append("Scan Summary\n", style="bold")
    banner_text.append("🎯 Target: ", style="bold")
    banner_text.append(
        f"{scanner.target} ({scanner.ip if hasattr(scanner, 'ip') else 'N/A'})\n"
    )
    banner_text.append("🔍 Scan Type: ", style="bold")
    banner_text.append(f"{scanner.scan_type.name.replace('_', ' ').title()}\n")
    banner_text.append("🕒 Timestamp: ", style="bold")
    banner_text.append(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    banner_text.append("📊 Ports: ", style="bold")
    banner_text.append(f"Scanned {total_ports}, ")
    banner_text.append(f"[green]Open: {open_count}[/green], ")
    banner_text.append(f"[red]Closed: {closed_count}[/red], ")
    banner_text.append(f"[yellow]Filtered: {filtered_count}[/yellow]")

    return Panel(
        banner_text,
        title="[bold]Cybersec CLI - Port Scan Results[/bold]",
        border_style="blue",
        padding=(1, 2),
        title_align="left",
    )


def format_scan_results_table(scanner: PortScanner) -> Table:
    """Format scan results as a rich Table.

    Args:
        scanner: PortScanner instance with scan results

    Returns:
        A rich Table object with scan results
    """
    # Create table with columns
    table = Table(
        title=f"🔍 Open Ports ({len([r for r in scanner.results if r.state == PortState.OPEN])} found)",
        box=box.ROUNDED,
        header_style="bold blue",
        show_header=True,
        show_lines=True,
        expand=True,
        border_style="blue",
        title_justify="left",
    )

    # Add columns with emoji indicators
    table.add_column("#", justify="right", style="dim", no_wrap=True)
    table.add_column("Port", justify="right", style="cyan", no_wrap=True)
    table.add_column("State", justify="center", style="green")
    table.add_column("Service", justify="left", style="yellow")
    table.add_column("Version", justify="left", style="magenta")
    table.add_column("Risk", justify="center", no_wrap=True)
    table.add_column("Details", justify="left", style="dim")

    # Add rows for open ports
    for idx, result in enumerate(sorted(scanner.results, key=lambda x: x.port), 1):
        if result.state != PortState.OPEN:
            continue

        # Get vulnerability info for risk assessment
        vuln_info = get_vulnerability_info(result.port)

        # Format port and state
        port = str(result.port)
        state = (
            Text("✓", style="green bold")
            if result.state == PortState.OPEN
            else Text("✗", style="red")
        )

        # Get service info
        service = Text(result.service.upper() if result.service else "unknown")
        version = Text(result.version if result.version else "-")

        # Format risk indicator
        risk_score = vuln_info.get("cvss_score", 0.0)
        if risk_score >= 9.0:
            risk = Text("CRITICAL", style="bold red")
        elif risk_score >= 7.0:
            risk = Text("HIGH", style="red")
        elif risk_score >= 4.0:
            risk = Text("MEDIUM", style="yellow")
        else:
            risk = Text("LOW", style="green")

        # Format banner/extra info
        banner = result.banner or ""
        if banner:
            if len(banner) > 40:  # Shorter banner for table view
                banner = banner[:37] + "..."

        # Add row to table with all columns
        table.add_row(str(idx), port, state, service, version, risk, banner or "-")

    return table


def generate_security_findings(scanner: PortScanner) -> List[Panel]:
    """Generate security findings from scan results.

    Args:
        scanner: PortScanner instance with scan results

    Returns:
        List of rich Panels with security findings
    """
    findings = []

    for result in sorted(scanner.results, key=lambda x: x.port):
        if result.state != PortState.OPEN:
            continue

        # Get vulnerability info
        vuln_info = get_vulnerability_info(result.port)

        # Skip if it's just an info finding and we have no additional details
        if (
            vuln_info["severity"] == Severity.INFO
            and not result.banner
            and not result.version
        ):
            continue

        # Create finding panel with rich text
        finding_text = Text()

        # Header with severity indicator
        finding_text.append("📌 ", style="bold")
        severity_style = _get_severity_style(vuln_info["severity"])
        finding_text.append(
            f"{vuln_info['description']}", style=severity_style + " bold"
        )

        # CVSS Score and Severity
        cvss_score = vuln_info.get("cvss_score", 0.0)
        if cvss_score > 0:
            finding_text.append("\n\n🔢 ", style="bold")
            finding_text.append("CVSS: ", style="bold")
            finding_text.append(f"{cvss_score:.1f}/10 ", style=severity_style + " bold")
            finding_text.append(f"({vuln_info['severity'].display_name})")

        # Exposure Information
        if "exposure" in vuln_info:
            finding_text.append("\n🌐 ", style="bold")
            finding_text.append("Exposure: ", style="bold")
            finding_text.append(vuln_info["exposure"])

        # Default Credentials Warning
        if "default_creds" in vuln_info and vuln_info["default_creds"]:
            finding_text.append("\n⚠️  ", style="bold")
            finding_text.append("Default Credentials: ", style="bold")
            finding_text.append(vuln_info["default_creds"])

        # MITRE ATT&CK
        if vuln_info.get("mitre_attack"):
            finding_text.append("\n🎯 ", style="bold")
            finding_text.append("MITRE ATT&CK: ", style="bold")
            finding_text.append(", ".join(vuln_info["mitre_attack"]))

        # Known Vulnerabilities (CVEs)
        if "cves" in vuln_info and vuln_info["cves"]:
            finding_text.append("\n\n🚨 ", style="bold")
            finding_text.append("Known Vulnerabilities:", style="bold")
            for cve in vuln_info["cves"]:
                finding_text.append(f"\n- {cve}")

        # Service Information
        finding_text.append("\n\n🔍 ", style="bold")
        finding_text.append("Service Information:", style="bold")
        if result.service:
            finding_text.append(f"\n- Service: {result.service.upper()}")
        if result.version:
            finding_text.append(f"\n- Version: {result.version}")
        if result.banner:
            banner = result.banner.strip()
            if len(banner) > 100:  # Truncate long banners
                banner = banner[:97] + "..."
            finding_text.append(f"\n- Banner: {banner}")

        # Detailed Recommendations
        finding_text.append("\n\n🛡️  ", style="bold")
        finding_text.append("Recommendations:", style="bold")
        finding_text.append(f"\n{vuln_info['recommendation']}")

        # Create panel with appropriate border color based on severity
        border_style = _get_severity_style(vuln_info["severity"])

        findings.append(
            Panel(
                finding_text,
                title=f"Port {result.port} - {vuln_info['severity'].display_name}",
                border_style=border_style,
                padding=(1, 2),
                title_align="left",
                expand=False,
            )
        )

    return findings


def format_scan_results_list(results: List[PortResult]) -> str:
    """Format scan results as a simple list with severity indicators.

    Args:
        results: List of PortResult objects

    Returns:
        Formatted string with one port per line
    """
    if not results:
        return "No ports were scanned."

    lines = []
    open_ports = [r for r in results if r.state == PortState.OPEN]

    if not open_ports:
        return "No open ports found."

    lines.append("🔍 Open Ports:")
    lines.append("=" * 50)

    for result in sorted(open_ports, key=lambda x: x.port):
        # Get vulnerability info
        vuln_info = get_vulnerability_info(result.port)

        # Format port and service
        port_info = f"Port {result.port}/tcp"
        if result.service:
            port_info += f" ({result.service.upper()})"

        # Add version if available
        if result.version:
            port_info += f" - Version: {result.version}"

        # Add severity indicator
        severity_emoji = {
            Severity.CRITICAL: "🔴",
            Severity.HIGH: "🟠",
            Severity.MEDIUM: "🟡",
            Severity.LOW: "🔵",
            Severity.INFO: "ℹ️",
        }.get(vuln_info["severity"], "")

        line = f"{severity_emoji} {port_info}"

        # Add banner preview
        if result.banner:
            banner = result.banner.replace("\n", " ")
            if len(banner) > 50:
                banner = banner[:47] + "..."
            line += f" - {banner}"

        lines.append(line)

        # Add vulnerability info
        if vuln_info.get("mitre_attack"):
            lines.append(f"   🎯 MITRE ATT&CK: {', '.join(vuln_info['mitre_attack'])}")
        lines.append(f"   ⚠️  {vuln_info['description']}")
        lines.append(f"   💡 {vuln_info['recommendation']}")
        lines.append("-" * 50)

    # Add summary
    lines.append("\n📊 Scan Summary:")
    lines.append("=" * 50)
    lines.append(f"Total ports scanned: {len(results)}")
    lines.append(f"Open ports: {len(open_ports)}")

    return "\n".join(lines)


def format_error(message: str, details: Optional[str] = None) -> Panel:
    """Format an error message in a panel.

    Args:
        message: Main error message
        details: Optional detailed error information

    Returns:
        A rich Panel with the error message
    """
    text = Text(message, style="bold red")
    if details:
        text.append("\n\n" + details, style="red")

    return Panel(
        text, title="Error", border_style="red", title_align="left", padding=(1, 2)
    )


def format_success(message: str) -> Panel:
    """Format a success message in a panel.

    Args:
        message: Success message

    Returns:
        A rich Panel with the success message
    """
    return Panel(
        Text(message, style="green"),
        title="Success",
        border_style="green",
        title_align="left",
        padding=(1, 2),
    )


def format_info(message: str) -> Panel:
    """Format an informational message in a panel.

    Args:
        message: Informational message

    Returns:
        A rich Panel with the info message
    """
    return Panel(
        Text(message, style="blue"),
        title="Info",
        border_style="blue",
        title_align="left",
        padding=(1, 2),
    )
