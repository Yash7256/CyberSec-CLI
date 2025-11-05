"""
Anomaly Detection Command for Cybersec CLI.
"""
import asyncio
import click
import logging
import time
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any, Optional, Set, Tuple
import random
import signal
import sys

from rich.console import Console
from rich.table import Table, Column
from rich.progress import (
    Progress, BarColumn, TextColumn, TimeElapsedColumn,
    TimeRemainingColumn, SpinnerColumn
)
from rich.panel import Panel
from rich.live import Live
from rich.layout import Layout
from rich.text import Text

from cybersec_cli.analysis.anomaly_detector import (
    NetworkAnomalyDetector,
    LogAnomalyDetector,
    Anomaly,
    AnomalyType,
    Protocol
)

console = Console()
logger = logging.getLogger(__name__)

# ANSI color codes
class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    RESET = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"

class AnomalyMonitor:
    """Monitors for anomalies with advanced features."""
    
    def __init__(self, interface: str = None, use_ml: bool = True):
        self.network_detector = NetworkAnomalyDetector(interface=interface, use_ml=use_ml)
        self.log_detector = LogAnomalyDetector()
        self.anomalies: List[Anomaly] = []
        self.alerted_anomalies: Set[str] = set()
        self.stats = {
            'start_time': time.time(),
            'anomalies_detected': 0,
            'network_anomalies': 0,
            'security_alerts': 0,
            'bytes_processed': 0,
            'connections_tracked': 0
        }
        self.interface = interface
        self.use_ml = use_ml
        self.running = True
        
        # Set up signal handler for graceful shutdown
        signal.signal(signal.SIGINT, self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)
    
    def _handle_signal(self, signum, frame):
        """Handle termination signals gracefully."""
        self.running = False
        console.print("\n[red]Shutting down gracefully...[/red]")
    
    def analyze_network_traffic(self) -> List[Anomaly]:
        """Analyze network traffic for anomalies using real system metrics."""
        try:
            return self.network_detector.analyze_traffic()
        except Exception as e:
            logger.error(f"Error analyzing network traffic: {e}")
            return []
    
    def analyze_logs(self) -> List[Anomaly]:
        """Analyze logs for anomalies."""
        return self.log_analyzer.analyze_logs()
    
    def generate_report(self, format: str = "text") -> str:
        """Generate a report of detected anomalies."""
        if format.lower() == "json":
            return self._generate_json_report()
        return self._generate_text_report()
    
    def _generate_text_report(self) -> str:
        """Generate a human-readable text report."""
        report = []
        runtime = time.time() - self.stats['start_time']
        
        # Summary
        report.append(f"\n{Colors.BOLD}=== Anomaly Detection Report ==={Colors.RESET}")
        report.append(f"Runtime: {timedelta(seconds=int(runtime))}")
        report.append(f"Network Interface: {self.interface or 'All'}")
        report.append(f"Anomalies Detected: {self.stats['anomalies_detected']}")
        report.append(f"Security Alerts: {self.stats['security_alerts']}")
        report.append(f"Connections Tracked: {self.stats['connections_tracked']}")
        
        # Top anomalies
        if self.anomalies:
            report.append(f"\n{Colors.BOLD}Top Anomalies:{Colors.RESET}")
            for i, anomaly in enumerate(sorted(
                self.anomalies, 
                key=lambda x: x.score, 
                reverse=True
            )[:5]):
                report.append(
                    f"{i+1}. [{anomaly.anomaly_type.upper()}] {anomaly.description} "
                    f"(Score: {anomaly.score:.1f})"
                )
        
        return "\n".join(report)
    
    def _generate_json_report(self) -> str:
        """Generate a JSON report of detected anomalies."""
        report = {
            'timestamp': datetime.utcnow().isoformat(),
            'runtime_seconds': time.time() - self.stats['start_time'],
            'interface': self.interface,
            'anomalies_detected': self.stats['anomalies_detected'],
            'network_anomalies': self.stats['network_anomalies'],
            'security_alerts': self.stats['security_alerts'],
            'bytes_processed': self.stats['bytes_processed'],
            'connections_tracked': self.stats['connections_tracked'],
            'anomalies': [
                {
                    'type': anomaly.anomaly_type,
                    'timestamp': anomaly.timestamp.isoformat() if hasattr(anomaly.timestamp, 'isoformat') else str(anomaly.timestamp),
                    'score': anomaly.score,
                    'description': anomaly.description,
                    'metadata': anomaly.metadata
                }
                for anomaly in sorted(self.anomalies, key=lambda x: x.score, reverse=True)[:100]
            ]
        }
        return json.dumps(report, indent=2)
    
    def save_report(self, filename: str = None):
        """Save the report to a file."""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"anomaly_report_{timestamp}.json"
        
        report = self.generate_report("json" if filename.endswith('.json') else 'text')
        
        try:
            with open(filename, 'w') as f:
                f.write(report)
            console.print(f"\n[green]Report saved to {filename}[/green]")
        except Exception as e:
            console.print(f"[red]Error saving report: {e}[/red]")
    
    def check_for_high_risk_anomalies(self) -> List[Anomaly]:
        """Check for high-risk anomalies that need immediate attention."""
        return [
            anomaly for anomaly in self.anomalies 
            if anomaly.score >= 8.0 and anomaly.anomaly_type in {
                AnomalyType.SECURITY_ALERT,
                AnomalyType.PORT_ACTIVITY,
                AnomalyType.CONNECTION_PATTERN
            }
        ]

def display_anomalies(anomalies: List[Anomaly], max_display: int = 20) -> None:
    """Display detected anomalies in a formatted table with severity-based coloring."""
    if not anomalies:
        console.print("[green]✓ No anomalies detected.[/green]")
        return
    
    # Sort by score (highest first) and limit display
    sorted_anomalies = sorted(anomalies, key=lambda x: x.score, reverse=True)
    display_count = min(len(sorted_anomalies), max_display)
    
    table = Table(
        title=f"Detected Anomalies (showing {display_count} of {len(anomalies)})",
        show_header=True,
        header_style="bold magenta",
        expand=True
    )
    
    # Add columns
    table.add_column("#", style="dim", width=4)
    table.add_column("Type", style="cyan", width=16)
    table.add_column("Time", style="yellow", width=20)
    table.add_column("Score", width=8)
    table.add_column("Description", style="white")
    
    # Add rows with color coding based on severity
    for i, anomaly in enumerate(sorted_anomalies[:max_display], 1):
        # Handle timestamp formatting
        if isinstance(anomaly.timestamp, (int, float)):
            timestamp_str = datetime.fromtimestamp(anomaly.timestamp).strftime("%Y-%m-%d %H:%M:%S")
        else:
            timestamp_str = anomaly.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        
        # Determine color based on score
        if anomaly.score >= 8.0:
            score_style = "bold red"
            anomaly_type = f"[bold red]{anomaly.anomaly_type.value.upper()}[/]"
        elif anomaly.score >= 6.0:
            score_style = "red"
            anomaly_type = f"[red]{anomaly.anomaly_type.value.title()}[/]"
        elif anomaly.score >= 4.0:
            score_style = "yellow"
            anomaly_type = f"[yellow]{anomaly.anomaly_type.value.title()}[/]"
        else:
            score_style = "white"
            anomaly_type = anomaly.anomaly_type.value.title()
        
        # Truncate long descriptions
        desc = (anomaly.description[:80] + '...') if len(anomaly.description) > 80 else anomaly.description
        
        table.add_row(
            str(i),
            anomaly_type,
            timestamp_str,
            f"[{score_style}]{anomaly.score:.2f}[/]",
            desc
        )
    
    # Add summary footer if there are more anomalies than displayed
    if len(anomalies) > max_display:
        table.caption = f"... and {len(anomalies) - max_display} more anomalies not shown"
    
    console.print(table)
    
    # Show high-risk alerts at the bottom
    high_risk = [a for a in sorted_anomalies if a.score >= 8.0]
    if high_risk:
        console.print("\n[bold red]! HIGH RISK ALERTS ![/]")
        for alert in high_risk[:3]:  # Show top 3 high-risk alerts
            console.print(f"  • {alert.description} ([red]Score: {alert.score:.1f}[/])")
        if len(high_risk) > 3:
            console.print(f"  ... and {len(high_risk) - 3} more high-risk alerts")

def create_ui_layout() -> Layout:
    """Create the TUI layout for real-time monitoring."""
    layout = Layout()
    
    # Split into header, main content, and footer
    layout.split(
        Layout(name="header", size=3),
        Layout(name="main", ratio=1),
        Layout(name="footer", size=3),
    )
    
    # Split main into metrics and anomalies
    layout["main"].split(
        Layout(name="metrics", size=10),
        Layout(name="anomalies", ratio=2),
        direction="vertical"
    )
    
    return layout

async def update_ui(progress: Progress, monitor: AnomalyMonitor, layout: Layout, 
                   duration: float, start_time: float) -> bool:
    """Update the UI with current metrics and anomalies."""
    try:
        # Calculate progress
        elapsed = time.time() - start_time
        progress.update(progress.tasks[0], completed=min(elapsed, duration))
        
        # Update metrics panel
        metrics_text = Text()
        metrics_text.append(f"Runtime: {timedelta(seconds=int(elapsed))} | ")
        metrics_text.append(f"Anomalies: {len(monitor.anomalies)} | ")
        metrics_text.append(f"High Risk: {len([a for a in monitor.anomalies if a.score >= 8.0])}")
        
        # Update layout
        layout["header"].update(
            Panel(
                "[bold blue]CyberSec Anomaly Detection",
                subtitle=f"Monitoring {monitor.interface or 'all interfaces'}"
            )
        )
        
        layout["metrics"].update(
            Panel(
                metrics_text,
                title="[bold]Metrics",
                border_style="blue"
            )
        )
        
        # Show recent anomalies
        if monitor.anomalies:
            recent_anomalies = sorted(monitor.anomalies, key=lambda x: x.timestamp, reverse=True)[:5]
            anomaly_text = Text()
            for anomaly in recent_anomalies:
                anomaly_text.append(
                    f"[{anomaly.anomaly_type}] {anomaly.description[:60]}...\n",
                    style="red" if anomaly.score >= 8.0 else "yellow"
                )
            layout["anomalies"].update(
                Panel(
                    anomaly_text or "No recent anomalies",
                    title="[bold]Recent Anomalies",
                    border_style="red" if any(a.score >= 8.0 for a in recent_anomalies) else "yellow"
                )
            )
        
        return elapsed < duration and monitor.running
        
    except Exception as e:
        logger.error(f"UI update error: {e}")
        return False

def register_commands(cli):
    """Register anomaly commands with the main CLI."""
    async def run_anomaly_detection(
        network: bool,
        logs: bool,
        duration: int,
        interval: float,
        interface: str,
        use_ml: bool,
        output: str,
        verbose: bool
    ):
        """Run the anomaly detection with the given parameters."""
        if not (network or logs):
            console.print("[yellow]Please specify at least one monitoring option (--network/--logs)[/yellow]")
            return
        
        monitor = AnomalyMonitor(interface=interface, use_ml=use_ml)
        start_time = time.time()
        end_time = start_time + duration
        
        # Configure progress bar
        progress_columns = [
            SpinnerColumn(),
            "• ",
            "[progress.description]{task.description}",
            "• ",
            BarColumn(bar_width=50),
            "• ",
            "[progress.percentage]{task.percentage:>3.0f}%",
            "• ",
            TimeRemainingColumn(),
            "• ",
            f"[dim]Anomalies: {len(monitor.anomalies)}"
        ]
        
        try:
            with Progress(*progress_columns, console=console) as progress:
                task = progress.add_task(
                    "[cyan]Monitoring for anomalies...",
                    total=duration,
                    start=False
                )
                
                # Initial delay to establish baseline
                if verbose:
                    console.print(f"[blue]Establishing baseline (first 10 seconds)...[/]")
                
                progress.start_task(task)
                last_anomaly_check = 0
                
                # Main monitoring loop
                while time.time() < end_time and monitor.running:
                    current_time = time.time()
                    
                    # Analyze traffic
                    if network:
                        try:
                            anomalies = monitor.analyze_network_traffic()
                            if anomalies:
                                monitor.anomalies.extend(anomalies)
                                monitor.stats['anomalies_detected'] += len(anomalies)
                                monitor.stats['network_anomalies'] += len(
                                    [a for a in anomalies if a.anomaly_type == AnomalyType.NETWORK_TRAFFIC]
                                )
                                monitor.stats['security_alerts'] += len(
                                    [a for a in anomalies if a.anomaly_type == AnomalyType.SECURITY_ALERT]
                                )
                                
                                # Display new anomalies
                                if verbose and time.time() - last_anomaly_check > 5:  # Throttle updates
                                    new_anomalies = [a for a in anomalies if a.score >= 6.0]
                                    if new_anomalies:
                                        display_anomalies(new_anomalies)
                                    last_anomaly_check = time.time()
                        except Exception as e:
                            logger.error(f"Error analyzing network traffic: {e}")
                    
                    # Update progress
                    elapsed = current_time - start_time
                    progress.update(task, completed=min(elapsed, duration))
                    
                    # Check for high-risk anomalies that need immediate attention
                    high_risk = monitor.check_for_high_risk_anomalies()
                    for alert in high_risk:
                        if alert.description not in monitor.alerted_anomalies:
                            console.print(
                                f"\n[bold red]! HIGH RISK ALERT ![/] {alert.description} "
                                f"(Score: {alert.score:.1f})"
                            )
                            monitor.alerted_anomalies.add(alert.description)
                    
                    # Sleep until next interval
                    await asyncio.sleep(max(0, interval - (time.time() - current_time)))
                
                # Generate and display final report
                console.print("\n[green]✓ Monitoring complete! Generating report...[/]")
                console.print(monitor.generate_report())
                
                # Save report if output file is specified
                if output:
                    monitor.save_report(output)
                
        except KeyboardInterrupt:
            console.print("\n[yellow]! Monitoring stopped by user[/]")
            if output:
                monitor.save_report(output)
        except Exception as e:
            console.print(f"[red]Error during monitoring: {e}[/]")
            logger.exception("An error occurred during monitoring:")
    
    # Create the Click command
    @cli.command()
    @click.option('--network', is_flag=True, help='Monitor network traffic')
    @click.option('--logs', is_flag=True, help='Monitor system logs')
    @click.option('--duration', type=int, default=300, help='Monitoring duration in seconds (default: 300)')
    @click.option('--interval', type=float, default=1.0, help='Check interval in seconds (default: 1.0)')
    @click.option('--interface', type=str, default=None, help='Network interface to monitor (default: all)')
    @click.option('--no-ml', is_flag=True, help='Disable machine learning detection')
    @click.option('--output', '-o', type=str, help='Save report to file (supports .json, .txt)')
    @click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
    def anomaly(network, logs, duration, interval, interface, no_ml, output, verbose):
        """
        Monitor system and network for anomalies.
        
        Examples:
          # Basic network monitoring (1 min)
          cybersec anomaly --network
          
          # Monitor specific interface with ML (5 min)
          cybersec anomaly --network --interface eth0 --duration 300
          
          # Save report to file
          cybersec anomaly --network --output report.json
        """
        asyncio.run(
            run_anomaly_detection(
                network=network,
                logs=logs,
                duration=duration,
                interval=interval,
                interface=interface,
                use_ml=not no_ml,
                output=output,
                verbose=verbose
            )
        )
