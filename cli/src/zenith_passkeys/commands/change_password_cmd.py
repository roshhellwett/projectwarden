import click
from rich.console import Console
from ..core.vault import VaultManager
from cryptography.exceptions import InvalidTag

console = Console()

@click.command(name="change-password")
def change_password():
    """Change the vault master password."""
    vault = VaultManager()
    if not vault.exists():
        console.print("[red]No vault found. Run 'zenith-passkeys init' first.[/red]")
        raise SystemExit(1)

    old_password = click.prompt("Current master password", hide_input=True)
    try:
        vault.unlock(old_password)
    except InvalidTag:
        console.print("[red]Wrong password.[/red]")
        raise SystemExit(1)

    new_password = click.prompt("New master password", hide_input=True, confirmation_prompt=True)
    if len(new_password) < 8:
        console.print("[red]Password must be at least 8 characters.[/red]")
        raise SystemExit(1)

    if new_password == old_password:
        console.print("[yellow]New password is the same as the old one. No change made.[/yellow]")
        return

    vault.change_password(old_password, new_password)
    console.print("[green]✓ Password changed successfully.[/green]")
