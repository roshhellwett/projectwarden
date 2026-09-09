import click
from cryptography.exceptions import InvalidTag
from rich.console import Console

from ..core.vault import VaultManager
from ._shared import handle_vault_error, require_vault

console = Console()


@click.command(name="change-password")
def change_password():
    """Change the vault master password."""
    vault = VaultManager()
    require_vault(vault)

    old_password = click.prompt("Current master password", hide_input=True)
    try:
        vault.unlock(old_password)
    except (InvalidTag, ValueError) as e:
        handle_vault_error(e)

    new_password = click.prompt("New master password", hide_input=True, confirmation_prompt=True)
    if len(new_password) < 8:
        console.print("[red]Password must be at least 8 characters.[/red]")
        raise SystemExit(1)

    if new_password == old_password:
        console.print("[yellow]New password is the same as the old one. No change made.[/yellow]")
        return

    vault.change_password(old_password, new_password)
    console.print("[green]✓ Password changed successfully.[/green]")
    console.print("[dim]Your recovery key is unchanged and still works.[/dim]")
