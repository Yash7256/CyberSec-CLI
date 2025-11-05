"""Scan command for Cybersec CLI.

Handles port scanning operations.
"""

import asyncio
import json
from pathlib import Path
from typing import Optional, List, Union, Dict, Any

import click
from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn

from cybersec_cli.tools.network import PortScanner, ScanType, PortResult, PortState
from cybersec_cli.utils.formatters import format_scan_results, format_scan_results_table, format_scan_results_list

console = Console()

@click.command("scan")
@click.argument("target")
@click.option(
    "-p", "--ports",
    help="Ports to scan (e.g., 80,443,8080 or 1-1024)",
    default=None
)
@click.option(
    "--scan-type",
    type=click.Choice([t.value for t in ScanType], case_sensitive=False),
    default=ScanType.TCP_CONNECT.value,
    help="Type of scan to perform"
)
@click.option(
    "--timeout",
    type=float,
    default=1.0,
    help="Connection timeout in seconds"
)
@click.option(
    "--concurrent",
    type=int,
    default=100,
    help="Maximum number of concurrent connections (same as --threads)"
)
@click.option(
    "--no-service-detection",
    is_flag=True,
    help="Disable service detection"
)
@click.option(
    "--rate-limit",
    type=int,
    default=0,
    help="Maximum requests per second (0 for no limit)"
)
@click.option(
    "--format",
    type=click.Choice(["table", "json", "csv", "list"], case_sensitive=False),
    default="table",
    help="Output format"
)
@click.option(
    "--output", "-o",
    type=click.Path(dir_okay=False, writable=True),
    help="Save results to file"
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    help="Show verbose output"
)
@click.option(
    "--log",
    type=click.Path(dir_okay=False, writable=True),
    help="Save log to file"
)
@click.option(
    "--no-banner",
    is_flag=True,
    help="Disable banner grabbing"
)
def scan_command(
    target: str,
    ports: Optional[str],
    scan_type: str,
    timeout: float,
    concurrent: int,
    no_service_detection: bool,
    rate_limit: int,
    no_banner: bool,
    output: Optional[str],
    format: str,
    verbose: bool,
    log: Optional[str]
) -> None:
    """
    Scan ports on a target host.
    
    Examples:
    
    \b
    # Scan common ports on example.com
    cybersec scan example.com
    
    \b
    # Scan specific ports with service detection
    cybersec scan 192.168.1.1 -p 80,443,8080
    
    \b
    # Scan a range of ports and save to file
    cybersec scan example.com -p 1-1024 --output scan_results.json
    """
    try:
        # Create scanner instance
        scanner = PortScanner(
            target=target,
            ports=ports,
            scan_type=ScanType(scan_type),
            timeout=timeout,
            max_concurrent=concurrent,
            service_detection=not no_service_detection,
            banner_grabbing=not no_banner
        )
        
        # Show progress
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=None),
            "[progress.percentage]{task.percentage:>3.0f}%",
            TimeRemainingColumn(),
            console=console
        ) as progress:
            task = progress.add_task(
                f"[cyan]Scanning {len(scanner.ports)} ports on {target}...",
                total=len(scanner.ports)
            )
            
            # Scan ports and update progress
            async def scan_with_progress():
                results = []
                
                async def check_port(port):
                    result = await scanner._check_port(port)
                    progress.update(task, advance=1)
                    return result
                
                # Create tasks for each port
                tasks = [check_port(port) for port in scanner.ports]
                
                # Run tasks and collect results
                for future in asyncio.as_completed(tasks):
                    result = await future
                    results.append(result)
                
                return results
            
            # Run the scan
            results = asyncio.run(scan_with_progress())
            scanner.results = sorted(results, key=lambda x: x.port)
        
        # Format and display results using the enhanced formatter
        if format == "table":
            # For table format, use the rich table with all features
            console.print(format_scan_results(scanner, format_type="table"))
            
            # If saving to file, convert to markdown for better readability
            if output:
                from rich.console import Console as RichConsole
                from rich.terminal_theme import MONOKAI
                
                # Create a console that writes to a file
                with open(output, 'w') as f:
                    file_console = RichConsole(file=f, force_terminal=True, force_interactive=False, width=120)
                    file_console.print(format_scan_results(scanner, format_type="table"))
                
                console.print(f"\n[green]Results saved to {output}[/green]")
                
        elif format == "list":
            # For list format, use the enhanced list formatter
            console.print(format_scan_results(scanner, format_type="list"))
            
            if output:
                with open(output, 'w') as f:
                    f.write(format_scan_results(scanner, format_type="list"))
                console.print(f"\n[green]Results saved to {output}[/green]")
                
        else:  # json format
            # For JSON, use the scanner's built-in JSON method
            json_output = scanner.to_json()
            console.print_json(json_output)
            
            if output:
                with open(output, 'w') as f:
                    f.write(json_output)
                console.print(f"\n[green]Results saved to {output}[/green]")
        
        # File saving is now handled in the format-specific blocks above
        
        # Show summary
        open_ports = len([r for r in scanner.results if r.state.name == "OPEN"])
        console.print(f"\n[bold]Scan complete:[/bold] {open_ports} open ports found")
        
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
