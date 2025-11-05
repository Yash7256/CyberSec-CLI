"""
Commands package for Cybersec CLI.
This module initializes and registers all available commands.
"""

def register_commands(cli):
    """Register all commands with the main CLI.
    
    Args:
        cli: The main Click command group
    """
    # Import and register the scan command
    from .scan import scan_command
    cli.add_command(scan_command)
    
    # Add more commands here as they are implemented
    from .harden import harden_command
    cli.add_command(harden_command)

    # Register anomaly detection commands
    from .anomaly import register_commands as register_anomaly_commands
    register_anomaly_commands(cli)
