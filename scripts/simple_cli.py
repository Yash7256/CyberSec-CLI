#!/usr/bin/env python3
"""Simple CLI with basic formatting."""
import shlex
from dataclasses import dataclass
from typing import List


@dataclass
class Command:
    name: str
    args: List[str]

    @classmethod
    def parse(cls, input_str: str) -> "Command":
        """Parse input string into a Command object."""
        parts = shlex.split(input_str.strip())
        if not parts:
            return cls("", [])
        return cls(parts[0].lower(), parts[1:])


def print_banner():
    """Print a simple banner."""
    print("\n" + "=" * 50)
    print("  Cybersec CLI - Simple Version")
    print("  Type 'help' for available commands")
    print("  Type 'exit' or 'quit' to exit")
    print("=" * 50 + "\n")


def show_help():
    """Show help information."""
    print("\nAvailable commands:")
    print("  help         - Show this help")
    print("  clear        - Clear the screen")
    print("  banner       - Show the banner")
    print("  scan <target>- Start a scan" " (e.g., 'scan example.com')")
    print("  exit/quit    - Exit the program")
    print()


def clear_screen():
    """Clear the terminal screen."""
    print("\033[H\033[J", end="")  # ANSI escape code to clear screen


def process_command(cmd: Command) -> bool:
    """Process a command and return whether to continue."""
    if not cmd.name:
        return True

    if cmd.name in ("exit", "quit"):
        print("\nExiting Cybersec CLI. Stay secure!")
        return False

    elif cmd.name in ("help", "?"):
        show_help()

    elif cmd.name == "clear":
        clear_screen()
        print_banner()

    elif cmd.name == "banner":
        print_banner()

    elif cmd.name == "scan":
        if not cmd.args:
            print("\n[!] Please specify a target to scan." " Example: scan example.com")
        else:
            target = cmd.args[0]
            print(f"\n[*] Starting scan of: {target}")
            # Simulate scanning
            print(f"[+] Checking if {target} is online...")
            print("[+] Scanning common ports...")
            print(f"[!] Scan completed for {target}")

    else:
        print(
            f"\n[!] Unknown command: {cmd.name}" " Type 'help' for available commands"
        )

    return True


def main():
    """Main CLI loop."""
    print_banner()

    try:
        while True:
            try:
                # Get user input
                try:
                    user_input = input("\ncybersec> ").strip()
                except (EOFError, KeyboardInterrupt):
                    print("\nUse 'exit' or 'quit' to exit the program")
                    continue

                # Parse and process command
                cmd = Command.parse(user_input)
                if not process_command(cmd):
                    break

            except Exception as e:
                print(f"\n[!] Error: {str(e)}")

    except Exception as e:
        print(f"\n[!] Fatal error: {str(e)}")
    finally:
        print("\nThank you for using Cybersec CLI!")


if __name__ == "__main__":
    main()
