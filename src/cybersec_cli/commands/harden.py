"""Security hardening commands for Cybersec CLI.

Handles system and service hardening operations.
"""

import os
import subprocess
import sys
from pathlib import Path
from typing import Dict, Optional

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()


def check_root():
    """Check if the script is running as root."""
    if os.geteuid() != 0:
        console.print(
            "[bold red]Error: This command requires root privileges. Please run with sudo.[/bold red]"
        )
        sys.exit(1)


def modify_config_file(filepath: str, settings: Dict[str, str]):
    """Modify a configuration file by replacing or adding key-value pairs."""
    with open(filepath, "r") as f:
        lines = f.readlines()

    # Create a set of keys for quick lookup
    keys_to_set = set(settings.keys())

    # Filter out existing lines that match the keys we want to set
    new_lines = [
        line for line in lines if line.strip().split(" ")[0] not in keys_to_set
    ]

    # Add the new settings to the end
    for key, value in settings.items():
        new_lines.append(f"{key} {value}\n")

    # Write the modified content back to the file
    with open(filepath, "w") as f:
        f.writelines(new_lines)


class SecurityHardener:
    """Handles security hardening operations."""

    def __init__(self):
        self.backup_dir = "/etc/cybersec/backups"
        self.setup_directories()

    def setup_directories(self):
        """Create necessary directories."""
        os.makedirs(self.backup_dir, exist_ok=True, mode=0o700)

    def backup_file(self, filepath: str) -> bool:
        """Backup a configuration file."""
        try:
            path = Path(filepath)
            if not path.exists():
                return True

            backup_path = Path(self.backup_dir) / f"{path.name}.bak"

            # Create backup
            with open(path, "r") as src, open(backup_path, "w") as dst:
                dst.write(src.read())

            os.chmod(backup_path, 0o600)
            return True

        except Exception as e:
            console.print(f"[red]Error backing up {filepath}: {str(e)}[/red]")
            return False

    def apply_ssh_hardening(self) -> bool:
        """Apply SSH server hardening."""
        sshd_config = "/etc/ssh/sshd_config"
        if not self.backup_file(sshd_config):
            return False

        settings_to_apply = {
            "Port": "2222",
            "Protocol": "2",
            "PermitRootLogin": "no",
            "MaxAuthTries": "3",
            "MaxSessions": "2",
            "ClientAliveInterval": "300",
            "ClientAliveCountMax": "2",
            "PasswordAuthentication": "no",
            "PubkeyAuthentication": "yes",
            "X11Forwarding": "no",
            "AllowTcpForwarding": "no",
            "PermitTunnel": "no",
            "AllowAgentForwarding": "no",
            "Ciphers": "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com",
            "MACs": "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com",
            "KexAlgorithms": "curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256",
        }
        try:
            modify_config_file(sshd_config, settings_to_apply)
            return True
        except Exception as e:
            console.print(f"[red]Error applying SSH hardening: {str(e)}[/red]")
            return False

    def configure_firewall(self) -> bool:
        """Configure UFW firewall with secure defaults."""
        try:
            cmds = [
                "ufw --force reset",
                "ufw default deny incoming",
                "ufw default allow outgoing",
                "ufw allow 2222/tcp",  # SSH
                "ufw allow 80/tcp",  # HTTP
                "ufw allow 443/tcp",  # HTTPS
                "ufw limit 2222/tcp",  # SSH brute force protection
                "ufw --force enable",
            ]

            for cmd in cmds:
                subprocess.run(cmd, shell=True, check=True, capture_output=True)

            return True

        except subprocess.CalledProcessError as e:
            console.print(f"[red]Error configuring firewall: {str(e)}[/red]")
            return False

    def install_security_tools(self) -> bool:
        """Install recommended security tools."""
        try:
            tools = ["fail2ban", "unattended-upgrades", "apt-listchanges", "aide"]

            subprocess.run(["apt-get", "update"], check=True, capture_output=True)

            subprocess.run(
                ["apt-get", "install", "-y"] + tools, check=True, capture_output=True
            )

            return True

        except subprocess.CalledProcessError as e:
            console.print(f"[red]Error installing security tools: {str(e)}[/red]")
            return False


@click.command("harden")
@click.argument("target", required=False)
@click.option("--all", is_flag=True, help="Apply all security hardening measures")
@click.option("--ssh", is_flag=True, help="Harden SSH server configuration")
@click.option("--firewall", is_flag=True, help="Configure UFW firewall")
@click.option(
    "--install-tools", is_flag=True, help="Install recommended security tools"
)
def harden_command(
    target: Optional[str], all: bool, ssh: bool, firewall: bool, install_tools: bool
):
    """Apply security hardening measures to the system.

    Examples:
      harden --all                       # Apply all hardening measures
      harden --ssh                       # Harden SSH configuration
      harden --firewall --install-tools  # Configure firewall and install tools
    """
    if not any([all, ssh, firewall, install_tools]):
        console.print(
            "[yellow]No hardening options specified. Use --help for available options.[/yellow]"
        )
        return

    # Hardening requires root privileges
    check_root()

    hardener = SecurityHardener()
    success = True

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        if all or ssh:
            task = progress.add_task("Harden SSH configuration...", total=1)
            if hardener.apply_ssh_hardening():
                progress.update(
                    task,
                    completed=1,
                    description="[green]SSH hardened successfully![/green]",
                )
            else:
                progress.update(task, description="[red]Failed to harden SSH[/red]")
                success = False

        if all or firewall:
            task = progress.add_task("Configuring firewall...", total=1)
            if hardener.configure_firewall():
                progress.update(
                    task, completed=1, description="[green]Firewall configured![/green]"
                )
            else:
                progress.update(
                    task, description="[red]Failed to configure firewall[/red]"
                )
                success = False

        if all or install_tools:
            task = progress.add_task("Installing security tools...", total=1)
            if hardener.install_security_tools():
                progress.update(
                    task,
                    completed=1,
                    description="[green]Security tools installed![/green]",
                )
            else:
                progress.update(
                    task, description="[red]Failed to install security tools[/red]"
                )
                success = False

    if success:
        console.print("\n[bold green]Hardening completed successfully![/bold green]")
        console.print(
            "[yellow]Note: Some changes may require a system restart to take effect.[/yellow]"
        )
    else:
        console.print("\n[bold red]Hardening completed with errors.[/bold red]")
        console.print(
            "Check the output above for details and ensure you have the necessary permissions."
        )


def register_commands(cli):
    """Register harden commands with the main CLI.

    Args:
        cli: The main Click command group
    """
    cli.add_command(harden_command)
