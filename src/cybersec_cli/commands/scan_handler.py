"""
Module for handling scan command implementation
"""
import time
from typing import List, Optional

from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn

from cybersec_cli.tools.network.port_scanner import PortScanner, ScanType, PortResult
from cybersec_cli.analysis.port_analyzer import analyze_scan_results
from cybersec_cli.ui.scan_output import create_scan_output

async def handle_scan(target: str, ports: Optional[List[int]] = None) -> Panel:
    """
    Handle the scan command execution
    
    Args:
        target: The target to scan
        ports: Optional list of ports to scan
        
    Returns:
        Panel containing scan results
    """
    try:
        # Initialize scanner
        scanner = PortScanner(
            target=target,
            ports=ports,
            scan_type=ScanType.TCP_CONNECT,
            timeout=2.0,
            max_concurrent=100,
            service_detection=True,
            banner_grabbing=True
        )
        
        # Run the scan
        start_time = time.time()
        results = await scanner.scan()
        scan_duration = time.time() - start_time
        
        if not results:
            return Panel("[yellow]No open ports found or scan was interrupted.[/]")
        
        # Process results
        open_ports = sorted(
            [r for r in results if r.state.value == "open"],
            key=lambda x: x.port
        )
        
        # Analyze for security findings
        findings = analyze_scan_results(open_ports)
        
        # Create output layout
        output_layout = create_scan_output(target, findings)
        return output_layout
        
    except Exception as e:
        return Panel(f"[red]Error during scan: {str(e)}[/]")