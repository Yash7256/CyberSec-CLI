"""Scan command for Cybersec CLI.

Handles port scanning operations.
"""

import asyncio
import csv
import io
import os
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel

from cybersec_cli.tools.network import PortScanner, ScanType
from cybersec_cli.utils.formatters import (
    format_scan_results,
    get_vulnerability_info,
    VULNERABILITY_DB
)
from cybersec_cli.core.validators import validate_target
# Import live enrichment
try:
    from cybersec_cli.utils.cve_enrichment import enrich_service_with_live_data
except ImportError:
    # Fallback
    async def enrich_service_with_live_data(*args): return []


console = Console()


@click.command("scan")
@click.argument("target")
@click.option(
    "-p", "--ports", help="Ports to scan (e.g., 80,443,8080 or 1-1024)", default=None
)
@click.option(
    "--scan-type",
    type=click.Choice([t.value for t in ScanType], case_sensitive=False),
    default=ScanType.TCP_CONNECT.value,
    help="Type of scan to perform",
)
@click.option(
    "--timeout", type=float, default=1.0, help="Connection timeout in seconds"
)
@click.option(
    "--concurrent",
    type=int,
    default=100,
    help="Maximum number of concurrent connections (same as --threads)",
)
@click.option("--no-service-detection", is_flag=True, help="Disable service detection")
@click.option(
    "--rate-limit",
    type=int,
    default=0,
    help="Maximum requests per second (0 for no limit)",
)
@click.option(
    "--format",
    type=click.Choice(["table", "json", "csv", "list"], case_sensitive=False),
    default="table",
    help="Output format",
)
@click.option(
    "--streaming",
    is_flag=True,
    help="Enable streaming scan results by priority (for web interface)",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(dir_okay=False, writable=True),
    help="Save results to file",
)
@click.option("--verbose", "-v", is_flag=True, help="Show verbose output")
@click.option(
    "--log", type=click.Path(dir_okay=False, writable=True), help="Save log to file"
)
@click.option("--no-banner", is_flag=True, help="Disable banner grabbing")
@click.option(
    "--require-reachable/--no-require-reachable",
    default=False,
    help="Require quick reachability (probe common web ports) before scanning",
)
@click.option(
    "--force",
    is_flag=True,
    help="Force the scan even if the target is a placeholder domain or other validations would block it",
)
@click.option(
    "--test",
    is_flag=True,
    help="Run a test scan against a safe, controlled target (scanme.nmap.org)",
)
@click.option(
    "--os", "--os-detection", is_flag=True,
    help="Perform OS detection using native fingerprinting",
)
@click.option(
    "--os-only", is_flag=True,
    help="Perform OS detection and show only OS information (suppresses port list)",
)
@click.option(
    "--adaptive/--no-adaptive",
    default=None,
    help="Enable/disable adaptive concurrency control (default: enabled from config)",
)
@click.option(
    "--enhanced-service-detection/--no-enhanced-service-detection",
    default=None,
    help="Enable/disable enhanced service detection (default: enabled from config)",
)
def scan_command(
    target: Optional[str],
    ports: Optional[str],
    scan_type: str,
    timeout: float,
    concurrent: int,
    no_service_detection: bool,
    rate_limit: int,
    no_banner: bool,
    test: bool,
    require_reachable: bool,
    force: bool,
    adaptive: Optional[bool],
    enhanced_service_detection: Optional[bool],
    os: bool,
    os_only: bool,
    output: Optional[str],
    format: str,
    verbose: bool,
    log: Optional[str],
    streaming: bool,
) -> None:
    """
    Scan ports on a target host.

    Examples:

    \b
    # Scan common ports on example.com
    cybersec scan example.com

    \b
    # Scan with OS detection only
    cybersec scan example.com --os-only

    \b
    # Scan specific ports with service detection
    cybersec scan 192.168.1.1 -p 80,443,8080

    \b
    # Scan a range of ports and save to file
    cybersec scan example.com -p 1-1024 --output scan_results.json
    """
    # Create scanner instance
    # If user passed --force, do not enforce reachability even if requested
    effective_require = require_reachable and not force

    # Resolve target once to prevent DNS rebinding attacks
    from src.cybersec_cli.core.validators import resolve_target
    resolved_ip = resolve_target(target)
    if not resolved_ip:
        click.echo(f"Error: Could not resolve target: {target}", err=True)
        return

    if test:
        if target and target != "scanme.nmap.org":
            click.echo(
                "Note: --test flag overrides the provided target with scanme.nmap.org"
            )
        target = "scanme.nmap.org"
        click.echo(f"Running test scan against {target} (safe for testing)")
    elif not target:
        raise click.UsageError("No target specified. Use --help for usage information.")

    # Validate target - reject private/reserved IP ranges
    if not validate_target(target, allow_private=False):
        raise click.UsageError("Scanning private IP ranges is not permitted")

    # Enable OS detection if --os-only is specified
    if os_only:
        os = True

    try:
        # Initialize the port scanner
        scanner = PortScanner(
            target=target,
            resolved_ip=resolved_ip,  # Pass pre-resolved IP to prevent DNS rebinding
            ports=ports,
            scan_type=ScanType(scan_type.lower()),
            timeout=timeout,
            max_concurrent=concurrent,
            service_detection=not no_service_detection,
            banner_grabbing=not no_banner,
            os_detection=os,
            rate_limit=rate_limit,
            require_reachable=effective_require,
            adaptive_scanning=adaptive,
            enhanced_service_detection=enhanced_service_detection,
            force_scan=force,
        )

        async def run_scan_and_enrich():
            """Run scan and enrichment in a single async context."""
            # Run the scan (use core scan path to keep caching/adaptive/priority features)
            results = await scanner.scan(streaming=streaming, force=force)
            scanner.results = sorted(results, key=lambda x: x.port)

            # If OS detection was enabled, trigger it now (after scan results are populated)
            if os:
                console.print("[cyan]Performing native OS fingerprinting...[/cyan]")
                os_info = scanner._perform_os_detection()
                scanner.os_info = os_info

            # Perform post-scan enrichment
            if not os_only:
                console.print("[cyan]Enriching results with live CVE data...[/cyan]")
                for result in scanner.results:
                    if result.state.name == "OPEN" and result.service and result.service != "unknown":
                        try:
                            live_cves = await enrich_service_with_live_data(result.service, result.version)
                            if live_cves:
                                if result.port not in VULNERABILITY_DB:
                                    base_info = get_vulnerability_info(result.port, result.service).copy()
                                    VULNERABILITY_DB[result.port] = base_info

                                current_entry = VULNERABILITY_DB[result.port]
                                existing_cves = set(current_entry.get("cves", []))
                                for cve in live_cves:
                                    cve_id = cve.get("id")
                                    if cve_id and cve_id not in existing_cves:
                                        current_entry.setdefault("cves", []).append(cve_id)
                        except Exception:
                            pass
            
            return scanner

        # Run the combined scan and enrichment
        scanner = asyncio.run(run_scan_and_enrich())

        # Handle output based on --os-only flag
        if os_only:
            # Print specialized OS-only output
            os_data = getattr(scanner, "os_info", {})
            if not os_data:
                os_data = {"error": "OS detection failed or yielded no results."}

            if "error" in os_data:
                console.print(Panel(f"[red]{os_data['error']}[/red]", title="OS Detection Result"))
            else:
                details = (
                    f"[bold]Target:[/bold] {target}\n"
                    f"[bold]Detected OS:[/bold] [green]{os_data.get('os_name', 'Unknown')}[/green]\n"
                    f"[bold]Accuracy:[/bold] {os_data.get('accuracy', 'N/A')}\n"
                    f"[bold]Details:[/bold] {os_data.get('details', '')}\n"
                )
                console.print(Panel(details, title="OS Fingerprinting Result", border_style="blue"))

            return

        # Format and display results using the enhanced formatter
        if format == "table":
            # For table format, use the rich table with all features
            console.print(format_scan_results(scanner, format_type="table"))

            # If saving to file, convert to markdown for better readability
            if output:
                from rich.console import Console as RichConsole

                # Create a console that writes to a file
                with open(output, "w") as f:
                    file_console = RichConsole(
                        file=f, force_terminal=True, force_interactive=False, width=120
                    )
                    file_console.print(
                        format_scan_results(scanner, format_type="table")
                    )

                console.print(f"\n[green]Results saved to {output}[/green]")

        elif format == "list":
            # For list format, use the enhanced list formatter
            console.print(format_scan_results(scanner, format_type="list"))

            if output:
                with open(output, "w") as f:
                    f.write(format_scan_results(scanner, format_type="list"))
                console.print(f"\n[green]Results saved to {output}[/green]")
        elif format == "csv":
            csv_buffer = io.StringIO()
            writer = csv.writer(csv_buffer)
            writer.writerow(
                [
                    "port",
                    "state",
                    "service",
                    "version",
                    "banner",
                    "protocol",
                    "confidence",
                ]
            )
            for result in scanner.results:
                writer.writerow(
                    [
                        result.port,
                        result.state.name if result.state else "",
                        result.service or "",
                        result.version or "",
                        result.banner or "",
                        result.protocol or "",
                        f"{result.confidence:.2f}" if result.confidence else "",
                    ]
                )
            csv_output = csv_buffer.getvalue()
            console.print(csv_output)

            if output:
                with open(output, "w", newline="") as f:
                    f.write(csv_output)
                console.print(f"\n[green]Results saved to {output}[/green]")

        else:  # json format
            # For JSON, use the scanner's built-in JSON method
            json_output = scanner.to_json()
            console.print_json(json_output)

            if output:
                with open(output, "w") as f:
                    f.write(json_output)
                console.print(f"\n[green]Results saved to {output}[/green]")

        # Show summary
        open_ports = len([r for r in scanner.results if r.state.name == "OPEN"])
        filtered_ports = len(
            [
                r
                for r in scanner.results
                if r.state.name == "OPEN_FILTERED" or r.state.name == "FILTERED"
            ]
        )
        console.print(f"\n[bold]Scan complete:[/bold] {open_ports} open ports found")
        if filtered_ports > 0 and scan_type.lower() == "udp":
            console.print(
                f"[bold]Note:[/bold] {filtered_ports} ports showed filtered responses (common with UDP scanning)"
            )

    except Exception as e:
        import sys

        # Use print for stderr since Rich's Console doesn't support file parameter
        print(f"Error: {str(e)}", file=sys.stderr)
        raise click.Abort()


# Register the command
def register_commands(cli):
    """Register scan commands with the main CLI.

    Args:
        cli: The main Click command group
    """
    cli.add_command(scan_command)
