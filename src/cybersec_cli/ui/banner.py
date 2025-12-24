"""
Banner and ASCII art for the Cybersec CLI.
"""

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.box import ROUNDED


def get_banner_content():
    """Return the banner content as a rich renderable."""
    banner = """
     ██████╗██╗   ██╗██████╗ ██████╗ ███████╗███████╗ ██████╗
    ██╔════╝╚██╗ ██╔╝██╔══██╗██╔══██╗██╔════╝██╔════╝██╔════╝
    ██║      ╚████╔╝ ██████╔╝██████╔╝███████╗█████╗  ██║           
    ██║       ╚██╔╝  ██╔══██╗██╔══██╗╚════██║██╔══╝  ██║            
    ╚██████╗   ██║   ██████╔╝██║  ██║███████║███████╗╚██████╗
     ╚═════╝   ╚═╝   ╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝
    """

    tagline = "AI-Powered Cybersecurity Assistant"
    version = "v0.1.0"

    return (
        Text(banner, style="bold green")
        + Text("\n" + " " * 8 + tagline, style="cyan")
        + Text("\n" + " " * 20 + version, style="dim")
    )


def show_banner():
    """Display the Cybersec CLI banner."""
    console = Console()

    # Create a styled banner with a border
    banner_panel = Panel(
        get_banner_content(), border_style="blue", box=ROUNDED, width=80, padding=(1, 2)
    )

    console.print(banner_panel, justify="center")

    # Print a warning message
    warning = (
        "[bold yellow]WARNING:[/] This tool is for authorized security testing only.\n"
        "Unauthorized access to computer systems is illegal.\n"
        "By continuing, you agree to use this tool ethically and legally."
    )

    console.print(Panel(warning, border_style="red", box=ROUNDED, width=80))
    console.print("")

    # Print quick help
    help_text = "[bold]Type 'help' for available commands or 'exit' to quit.[/]"
    console.print(help_text, justify="center")
    console.print("")


def show_scan_banner(scan_type: str, target: str):
    """Display a banner for scan operations."""
    console = Console()
    console.print("\n" + "=" * 80)
    console.print(
        f"[bold cyan]Starting {scan_type.upper()} scan on:[/] [bold white]{target}[/]"
    )
    console.print("=" * 80 + "\n")
