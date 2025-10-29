"""Output formatters for Cybersec CLI."""

from typing import List, Dict, Any, Optional

from rich.table import Table
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from cybersec_cli.tools.network import PortResult, PortScanner, PortState

def format_scan_results(scanner: PortScanner, format_type: str = "table") -> str:
    """Format port scan results in the specified format.
    
    Args:
        scanner: PortScanner instance with scan results
        format_type: Output format (table, json, list)
        
    Returns:
        Formatted results as a string
    """
    if format_type == "json":
        return scanner.to_json()
    
    if format_type == "list":
        return format_scan_results_list(scanner.results)
    
    # Default to table format
    return format_scan_results_table(scanner)

def format_scan_results_table(scanner: PortScanner) -> Table:
    """Format scan results as a rich Table.
    
    Args:
        scanner: PortScanner instance with scan results
        
    Returns:
        A rich Table object with scan results
    """
    table = Table(
        title=f"Port Scan Results for {scanner.target}",
        box=box.ROUNDED,
        header_style="bold magenta",
        show_header=True,
        show_lines=True,
        expand=True
    )
    
    # Add columns
    table.add_column("Port", justify="right")
    table.add_column("State", justify="center")
    table.add_column("Service", justify="left")
    table.add_column("Banner", justify="left")
    table.add_column("Version", justify="left")
    
    # Add rows
    for result in sorted(scanner.results, key=lambda x: x.port):
        if result.state != PortState.OPEN:
            continue
            
        # Format port and state
        port = str(result.port)
        state = f"[green]{result.state.name}[/green]"
        
        # Format service
        service = result.service or "unknown"
        service = service.upper()
        
        # Format banner and version
        banner = result.banner or ""
        version = result.version or ""
        
        # Truncate long banners
        if len(banner) > 50:
            banner = banner[:47] + "..."
        
        table.add_row(port, state, service, banner, version)
    
    return table

def format_scan_results_list(results: List[PortResult]) -> str:
    """Format scan results as a simple list.
    
    Args:
        results: List of PortResult objects
        
    Returns:
        Formatted string with one port per line
    """
    lines = []
    
    for result in sorted(results, key=lambda x: x.port):
        if result.state != PortState.OPEN:
            continue
            
        line = f"Port {result.port}/tcp"
        
        if result.service:
            line += f" {result.service.upper()}"
            
        if result.version:
            line += f" {result.version}"
            
        if result.banner:
            banner = result.banner.replace("\n", " ")
            if len(banner) > 50:
                banner = banner[:47] + "..."
            line += f" - {banner}"
            
        lines.append(line)
    
    return "\n".join(lines) if lines else "No open ports found"

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
        text,
        title="Error",
        border_style="red",
        title_align="left",
        padding=(1, 2)
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
        padding=(1, 2)
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
        padding=(1, 2)
    )
