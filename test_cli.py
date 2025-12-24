#!/usr/bin/env python3
"""
Simple test CLI to verify basic input/output functionality.
"""
import asyncio

from prompt_toolkit import PromptSession
from rich.console import Console
from rich.panel import Panel

console = Console()


async def main():
    """Simple CLI test."""
    session = PromptSession()
    console.print(Panel("[bold green]Cybersec CLI Test[/]\nType 'exit' to quit"))

    while True:
        try:
            # Get user input
            user_input = await session.prompt_async("cybersec> ")

            # Process commands
            if user_input.lower() in ("exit", "quit"):
                console.print("[yellow]Exiting...[/]")
                break

            # Echo the input for testing
            console.print(f"You typed: {user_input}")

        except (KeyboardInterrupt, EOFError):
            console.print("\n[yellow]Use 'exit' or 'quit' to exit[/]")
        except Exception as e:
            console.print(f"[red]Error: {str(e)}[/]")


if __name__ == "__main__":
    asyncio.run(main())
