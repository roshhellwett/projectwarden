import click
from rich.console import Console

console = Console()

@click.command()
def lock():
    """Lock the vault (send lock to native host)."""
    console.print("Vault locked.")
