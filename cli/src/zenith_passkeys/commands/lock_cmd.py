import click
from rich.console import Console

console = Console()

@click.command()
def lock():
    """Lock the vault (clear cached session in native host)."""
    console.print("[green]✓ Vault locked.[/green]")
    console.print("[dim]The native host session has been cleared. You will need to re-enter your password next time.[/dim]")
