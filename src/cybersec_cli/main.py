#!/usr/bin/env python3
"""
Cybersec CLI - Main entry point for the cybersecurity assistant.
"""
import asyncio
import logging
import shlex
import sys
from datetime import datetime
from pathlib import Path

import click
from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from cybersec_cli.config import settings
from cybersec_cli.ui.banner import get_banner_content
from cybersec_cli.ui.themes import load_theme
from cybersec_cli.utils.logger import setup_logger

# Set up logging
logger = setup_logger(__name__)

# Initialize console with theme
console = Console(theme=load_theme(settings.ui.theme))

# Import commands after settings are loaded
try:
    from cybersec_cli.commands import register_commands
except ImportError as e:
    logger.error(f"Failed to import commands: {e}")
    raise


class CyberSecCLI:
    def __init__(self):
        self.running = True
        self.current_context = {}
        self.command_history = []
        self.layout = None

    async def start(self):
        """Start the interactive CLI session."""
        self.setup_layout()
        await self.interactive_loop()

    def setup_layout(self):
        """Set up the Rich layout with banner and content areas."""
        from rich.layout import Layout
        from rich.panel import Panel
        from rich.text import Text

        self.layout = Layout()
        self.layout.split_column(
            Layout(name="header", size=15),
            Layout(name="content", ratio=1),
            Layout(name="footer", size=1),
        )

        # Add banner to header
        banner_panel = Panel(get_banner_content(), border_style="blue", padding=(1, 2))
        self.layout["header"].update(banner_panel)

        # Add initial content
        content_panel = Panel(
            Text.from_markup(
                "[bold cyan]Welcome to Cybersec CLI![/]\n\n"
                "Type 'help' to see available commands\n"
                "Type 'exit' or 'quit' to exit\n\n"
                "[dim]Initializing...[/]"
            )
        )
        self.layout["content"].update(content_panel)

        # Add status bar
        self.update_footer()

    def update_footer(self, message: str = ""):
        """Update the footer with status information."""
        from rich.text import Text

        context_info = []
        if self.current_context.get("target"):
            context_info.append(f"Target: {self.current_context['target']}")
        if self.current_context.get("scan_type"):
            context_info.append(f"Scan: {self.current_context['scan_type']}")

        status = (
            " | ".join(context_info) if context_info else "Type 'help' for commands"
        )
        if message:
            status = f"{message} | {status}"

        self.layout["footer"].update(Text.from_markup(f"[dim]{status}[/]"))

    async def interactive_loop(self):
        """Main interactive loop for the CLI."""
        from prompt_toolkit import PromptSession
        from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
        from prompt_toolkit.history import FileHistory
        from rich.live import Live

        # Initialize the Live display
        live = Live(self.layout, refresh_per_second=4, screen=True)
        live.start()

        try:
            # Initialize prompt session
            history = FileHistory(str(Path.home() / ".cybersec_history"))
            session = PromptSession(
                history=history,
                auto_suggest=AutoSuggestFromHistory(),
                complete_while_typing=True,
            )

            # Initial update to show we're ready
            help_text = (
                "[bold cyan]Cybersec CLI Ready![/]\n\n"
                "Type 'help' for available commands\n"
                "Type 'exit' or 'quit' to exit"
            )
            self.layout["content"].update(
                Panel(Text.from_markup(help_text), title="[bold]Help[/]")
            )
            live.refresh()

            while self.running:
                try:
                    # Get user input
                    user_input = await session.prompt_async(
                        "[bold cyan]cybersec>[/] ",
                        bottom_toolbar=self._get_bottom_toolbar(),
                    )

                    if not user_input.strip():
                        continue

                    # Process the command
                    self.command_history.append(user_input)
                    await self.process_command(user_input)

                except (KeyboardInterrupt, EOFError):
                    self.running = False
                    self.layout["content"].update(
                        Panel(
                            "[yellow]Exiting Cybersec CLI. Stay secure![/]",
                            title="[bold]Exit[/]",
                        )
                    )
                    live.refresh()
                    break
                except Exception as e:
                    self.layout["content"].update(
                        Panel(f"[red]Error: {str(e)}[/]", title="[bold]Error[/]")
                    )
                    live.refresh()
        finally:
            # Ensure Live display is properly stopped
            if live.is_started:
                live.stop()

    def _get_bottom_toolbar(self):
        """Get the bottom toolbar text based on current context."""
        context_info = []
        if self.current_context.get("target"):
            context_info.append(f"Target: {self.current_context['target']}")
        if self.current_context.get("scan_type"):
            context_info.append(f"Scan: {self.current_context['scan_type']}")

        return " | ".join(context_info) if context_info else "Type 'help' for commands"

    async def process_command(self, command: str):
        """Process user commands."""
        from rich.panel import Panel
        from rich.text import Text

        command = command.strip()
        if not command:
            return

        # Split command into parts
        try:
            parts = shlex.split(command)

            if not parts:
                return

            cmd = parts[0].lower()
            args = parts[1:]

            if cmd in ("exit", "quit"):
                self.running = False
                self.update_footer("Exiting...")
                self.layout["content"].update(
                    Panel(
                        Text.from_markup(
                            "[yellow]Exiting Cybersec CLI. Stay secure![/]"
                        )
                    )
                )
            elif cmd in ("help", "?"):
                self.show_help()
            elif cmd == "clear":
                self.layout["content"].update(
                    Panel(
                        Text.from_markup("Cleared. Type 'help' for available commands.")
                    )
                )
            elif cmd == "scan":
                if not args:
                    self.layout["content"].update(
                        Panel(
                            Text.from_markup(
                                "[yellow]Please specify a target to scan.\nExample: scan example.com[/]"
                            )
                        )
                    )
                else:
                    await self.handle_scan_command(" ".join(args))
            elif cmd == "banner":
                from cybersec_cli.ui.banner import get_banner_content

                self.layout["header"].update(
                    Panel(get_banner_content(), border_style="blue", padding=(1, 2))
                )
                self.layout["content"].update(
                    Panel(Text.from_markup("Banner refreshed!"))
                )
            else:
                self.layout["content"].update(
                    Panel(
                        Text.from_markup(
                            f"[red]Unknown command: {cmd}[/]\n\n"
                            "Type [bold]'help'[/] for available commands"
                        )
                    )
                )

        except Exception as e:
            self.layout["content"].update(
                Panel(Text.from_markup(f"[red]Error processing command: {str(e)}[/]"))
            )

    async def handle_scan_command(self, args: str):
        """Handle scan commands."""
        # note: top-level imports include `from datetime import datetime`
        # avoid re-importing `datetime` module here which would shadow
        # the `datetime` class and break calls like `datetime.now()`.
        from rich.layout import Layout
        from rich.panel import Panel
        from rich.text import Text

        from cybersec_cli.analysis.port_analyzer import analyze_scan_results
        from cybersec_cli.tools.network.port_scanner import PortScanner, ScanType

        # Parse arguments
        parts = args.split()
        if not parts:
            self.layout["content"].update(
                Panel(
                    Text.from_markup(
                        "[yellow]Please specify a target to scan. Example: scan example.com[/]"
                    )
                )
            )
            return

        target = parts[0]
        ports = None  # Default to common ports

        # Support simple flags in interactive scan: --require-reachable and --force
        require_reachable = False
        force = False
        if "--require-reachable" in parts:
            require_reachable = True
            # remove flag so port parsing below is not confused
            parts = [p for p in parts if p != "--require-reachable"]
        if "--force" in parts:
            force = True
            parts = [p for p in parts if p != "--force"]

        # Simple argument parsing (can be enhanced with argparse/click later)
        if "-p" in parts:
            try:
                port_arg = parts[parts.index("-p") + 1]
                if "-" in port_arg:
                    # Port range (e.g., 1-1024)
                    start, end = map(int, port_arg.split("-"))
                    ports = list(range(start, end + 1))
                elif "," in port_arg:
                    # Comma-separated ports
                    ports = [int(p) for p in port_arg.split(",")]
                else:
                    # Single port
                    ports = [int(port_arg)]
            except (ValueError, IndexError):
                self.layout["content"].update(
                    Panel(
                        Text.from_markup(
                            "[red]Invalid port specification. Use: -p PORT, -p START-END, or -p PORT1,PORT2,...[/]"
                        )
                    )
                )
                return

        # Update UI to show scanning has started
        self.layout["content"].update(
            Panel(
                Text.from_markup(
                    f"[yellow]Scanning {target}... This may take a moment.[/]"
                )
            )
        )

        try:
            # Initialize and run the scanner
            effective_require = require_reachable and not force
            scanner = PortScanner(
                target=target,
                ports=ports,
                scan_type=ScanType.TCP_CONNECT,
                timeout=2.0,
                max_concurrent=100,
                service_detection=True,
                banner_grabbing=True,
                require_reachable=effective_require,
            )

            # Run the scan with timing
            import time

            start_time = time.time()
            results = await scanner.scan()
            time.time() - start_time

            # Process and display results
            if not results:
                self.layout["content"].update(
                    Panel("[yellow]No open ports found or scan was interrupted.[/]")
                )
                return

            # Filter open ports and sort by port number
            open_ports = sorted(
                [r for r in results if r.state.value == "open"], key=lambda x: x.port
            )

            # Analyze results for security findings
            findings = analyze_scan_results(open_ports)

            # Import the scan output formatter

            output_layout = Layout()

            # Count findings by severity
            severity_counts = {"High": 0, "Medium": 0, "Low": 0, "Info": 0}
            for f in findings:
                severity_counts[f["severity"]] += 1

            # Create summary text
            findings_summary = (
                f"[red]{severity_counts['High']} High[/], "
                f"[yellow]{severity_counts['Medium']} Medium[/], "
                f"[cyan]{severity_counts['Low']} Low[/], "
                f"[dim]{severity_counts['Info']} Info[/]"
            )

            # Create summary panel
            summary_panel = Panel(
                Text.from_markup(
                    f"🎯 [bold]Target:[/] {target}\n"
                    f"🕒 [bold]Timestamp:[/] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                    f"📊 [bold]Findings:[/] {findings_summary}"
                ),
                title="[bold]Scan Summary[/]",
                border_style="blue",
            )

            # Group findings by severity and create recommendations
            findings_by_severity = {"High": [], "Medium": [], "Low": []}

            for finding in findings:
                severity = finding["severity"]
                if severity in findings_by_severity:
                    findings_by_severity[severity].append(finding)

            # Create recommended actions text with emojis and formatting
            actions_text = "[bold]🔧 Recommended Actions (By Priority)[/]\n\n"

            severity_emojis = {"High": "🔴", "Medium": "🟠", "Low": "🟢"}

            severity_colors = {"High": "red", "Medium": "yellow", "Low": "green"}

            for severity, emoji in severity_emojis.items():
                if findings_by_severity[severity]:
                    actions_text += f"[bold {severity_colors[severity]}]{emoji} {severity} Severity[/]\n\n"
                    for finding in findings_by_severity[severity]:
                        port_info = f"[bold]{finding['finding']}[/]\n\n"

                        # Format recommendations as bullet points
                        recommendations = finding.get("recommendation", "").split("\n")
                        recommendations = [
                            r.strip() for r in recommendations if r.strip()
                        ]
                        recommendations = [
                            r.replace("1. ", "• ") if r.startswith("1. ") else f"• {r}"
                            for r in recommendations
                        ]

                        actions_text += port_info + "\n".join(recommendations) + "\n\n"

            # Add remediation scope section
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

            summary_panel = Panel(
                Text.from_markup(
                    f"🎯 [bold]Target:[/] {target}\n"
                    f"🕒 [bold]Timestamp:[/] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                    f"📊 [bold]Findings:[/] {findings_summary}"
                ),
                title="[bold]Scan Summary & Findings[/]",
                border_style="blue",
                expand=False,
            )

            # --- Findings and Recommendations Panels ---
            finding_panels = []
            actions_panel = Panel(
                Text.from_markup(actions_text),
                title="[bold]Recommended Actions & Scope[/]",
                border_style="blue",
                expand=False,
            )

            # --- Technical Findings Panels ---
            severity_order = {"High": 1, "Medium": 2, "Low": 3, "Info": 4}
            sorted_findings = sorted(
                findings, key=lambda x: severity_order.get(x["severity"], 5)
            )

            for finding in sorted_findings:
                severity = finding["severity"]
                color = {"High": "red", "Medium": "yellow", "Low": "cyan"}.get(
                    severity, "dim"
                )

                # Enhanced technical details with grid layout
                tech_details = Table.grid(padding=(0, 2))

                # CVSS Score and Vector
                cvss = finding.get("cvss", {})
                cvss_score = cvss.get("score", 0)
                cvss_color = (
                    "red"
                    if cvss_score >= 7.0
                    else "yellow" if cvss_score >= 4.0 else "green"
                )
                tech_details.add_row(
                    "🔍 [bold]CVSS Score:[/]",
                    f"[{cvss_color}]{cvss_score:.1f}[/] ({cvss.get('severity', 'N/A')})",
                )
                tech_details.add_row(
                    "🎯 [bold]CVSS Vector:[/]", f"[dim]{cvss.get('vector', 'N/A')}[/]"
                )
                tech_details.add_row(
                    "💫 [bold]Impact:[/]", f"{cvss.get('impact', 'N/A'):.1f}"
                )
                tech_details.add_row(
                    "⚡ [bold]Exploitability:[/]",
                    f"{cvss.get('exploitability', 'N/A'):.1f}",
                )

                # Exploitability Details
                exploit_info = finding.get("exploitability", {})
                tech_details.add_row("", "")  # Spacer
                tech_details.add_row(
                    "🔬 [bold]Exploit Maturity:[/]",
                    f"{exploit_info.get('maturity', 'Unknown')} "
                    + ("🔴" if exploit_info.get("public_exploits") else "🟢"),
                )
                tech_details.add_row(
                    "📊 [bold]Ease of Exploit:[/]",
                    exploit_info.get("ease_of_exploit", "Unknown"),
                )

                # Confidence Level
                confidence = finding.get("confidence", 0) * 100
                confidence_color = (
                    "green"
                    if confidence >= 80
                    else "yellow" if confidence >= 50 else "red"
                )
                tech_details.add_row("", "")  # Spacer
                tech_details.add_row(
                    "🎯 [bold]Detection Confidence:[/]",
                    f"[{confidence_color}]{confidence:.0f}%"
                    + (
                        " (High)"
                        if confidence >= 80
                        else " (Medium)" if confidence >= 50 else " (Low)"
                    )
                    + "[/]",
                )

                # CWE and Compliance
                tech_details.add_row("", "")  # Spacer
                tech_details.add_row(
                    "📋 [bold]CWE ID:[/]", finding.get("cwe_id", "N/A")
                )

                # Format MITRE ATT&CK TTPs if present
                mitre_attack = finding.get("mitre_attack", [])
                if mitre_attack:
                    tech_details.add_row(
                        "🎯 [bold]MITRE ATT&CK:[/]",
                        ", ".join([f"[cyan]{t}[/]" for t in mitre_attack]),
                    )

                # Ensure compliance is rendered as text
                compliance_val = finding.get("compliance", "N/A")
                if isinstance(compliance_val, list):
                    compliance_str = "\n    ".join(compliance_val)
                else:
                    compliance_str = str(compliance_val)
                tech_details.add_row("� [bold]Compliance:[/]", compliance_str)

                # Format the content with technical details
                finding_content = [
                    f'📄 [bold]Finding:[/] {finding["finding"]}',
                    "-" * 60,
                    f'🔬 [bold]Details:[/] {finding["details"]}',
                    "",
                    f"⚠️  [bold]Risk Impact:[/]",
                    finding.get(
                        "impact",
                        "Potential security vulnerability that could lead to unauthorized access or data exposure.",
                    ),
                    "",
                    f"🛡️  [bold]Recommendations:[/]",
                    finding.get(
                        "recommendation", "No specific recommendations available."
                    ),
                    "",
                    str(tech_details),
                ]
                content = "\n".join(finding_content)

                finding_panels.append(
                    Panel(
                        Text.from_markup(content),
                        title=f"[bold]Port {finding['port']} - [{color}]{severity}[/][/]",
                        border_style=color,
                        expand=False,
                    )
                )

            # Assemble the final layout
            output_layout.split_column(summary_panel, *finding_panels)

            # Update the content with the results
            self.layout["content"].update(output_layout)

        except Exception as e:
            self.layout["content"].update(Panel(f"[red]Error during scan: {str(e)}[/]"))

    def show_help(self):
        """Display help information."""
        from rich.panel import Panel

        help_text = """[bold cyan]Cybersec CLI - Help[/bold cyan]

[bold]Available Commands:[/bold]
  [bold]help[/bold]                    Show this help message
  [bold]scan[/bold] <target> [options]  Scan a target (use --help for scan options)
  [bold]clear[/bold]                   Clear the screen
  [bold]banner[/bold]                  Redisplay the banner
  [bold]exit[/bold]/[bold]quit[/bold]             Exit the program

[bold]Scan Examples:[/bold]
  [dim]# Basic scan[/dim]
  scan example.com

  [dim]# Scan specific ports[/dim]
  scan example.com -p 80,443,8080

  [dim]# Scan a port range[/dim]
  scan 192.168.1.1 -p 1-1024

  [dim]# Save results to a file[/dim]
  scan example.com -o results.txt

  [dim]# Show scan help[/dim]
  scan --help

[bold]Shortcuts:[/bold]
  [dim]↑/↓[/dim]  Navigate command history
  [dim]Tab[/dim]   Auto-complete commands
  [dim]Ctrl+C[/dim] Cancel current operation
  [dim]Ctrl+D[/dim] Exit the program"""

        # Update the content panel with help text
        self.layout["content"].update(  # type: ignore
            Panel(help_text, border_style="blue")
        )


def run_cybersec_cli():
    """Run the Cybersec CLI in interactive mode."""
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
        handlers=[RichHandler(console=console)],
    )

    # Create and run the CLI
    cli_inst = CyberSecCLI()
    asyncio.run(cli_inst.start())


# Create the main CLI group
@click.group(invoke_without_command=True)
@click.option(
    "-v",
    "--verbose",
    count=True,
    help="Increase verbosity (can be used multiple times)",
)
@click.option("--debug", is_flag=True, help="Enable debug mode")
@click.pass_context
def cli(ctx: click.Context, verbose: int, debug: bool):
    """Cybersec CLI - Your AI-powered cybersecurity assistant."""
    # Configure logging based on verbosity
    log_level = logging.WARNING
    if verbose == 1:
        log_level = logging.INFO
    elif verbose >= 2 or debug:
        log_level = logging.DEBUG

    # Configure logging
    logging.basicConfig(
        level=log_level, format="%(message)s", handlers=[RichHandler(console=console)]
    )

    if debug:
        logger.setLevel(logging.DEBUG)
        logger.debug("Debug mode enabled")

    # Store context for subcommands
    ctx.ensure_object(dict)
    ctx.obj["debug"] = debug
    ctx.obj["verbose"] = verbose

    # If no command is provided, run in interactive mode
    if ctx.invoked_subcommand is None:
        run_cybersec_cli()


# Add commands directly to the CLI group
register_commands(cli)

if __name__ == "__main__":
    # If no arguments, run in interactive mode
    if len(sys.argv) == 1:
        run_cybersec_cli()
    else:
        cli()
