"""Output formatters for Cybersec CLI."""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from rich import box
from rich.console import Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from cybersec_cli.tools.network import PortResult, PortScanner, PortState


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
    },
}


def get_vulnerability_info(port: int, service: Optional[str] = None) -> Dict[str, Any]:
    """Get vulnerability information for a given port and service.

    Args:
        port: Port number
        service: Service name (optional)

    Returns:
        Dictionary with vulnerability information
    """
    # First try exact port match
    if port in VULNERABILITY_DB:
        return VULNERABILITY_DB[port]

    # Try to match by service name if provided
    if service:
        service = service.lower()
        for port_num, info in VULNERABILITY_DB.items():
            if isinstance(port_num, int) and info.get("service", "").lower() == service:
                return info

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
    banner_text.append(f"🎯 Target: ", style="bold")
    banner_text.append(
        f"{scanner.target} ({scanner.ip if hasattr(scanner, 'ip') else 'N/A'})\n"
    )
    banner_text.append(f"🔍 Scan Type: ", style="bold")
    banner_text.append(f"{scanner.scan_type.name.replace('_', ' ').title()}\n")
    banner_text.append(f"🕒 Timestamp: ", style="bold")
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
        vuln_info = get_vulnerability_info(result.port, result.service)

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
        vuln_info = get_vulnerability_info(result.port, result.service)

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
        finding_text.append(f"📌 ", style="bold")
        severity_style = vuln_info["severity"].value[1]
        finding_text.append(
            f"{vuln_info['description']}", style=severity_style + " bold"
        )

        # CVSS Score and Severity
        cvss_score = vuln_info.get("cvss_score", 0.0)
        if cvss_score > 0:
            finding_text.append(f"\n\n🔢 ", style="bold")
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

        # Known Vulnerabilities
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
        border_style = vuln_info["severity"].value[1]

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
        vuln_info = get_vulnerability_info(result.port, result.service)

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
