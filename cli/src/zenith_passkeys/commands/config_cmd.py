import click
from cryptography.exceptions import InvalidTag
from rich.console import Console

from ..core.vault import VaultManager
from ._shared import handle_vault_error, require_vault

console = Console()


@click.command()
@click.option("--idle-timeout", type=int, default=None, help="Idle timeout in minutes")
def config(idle_timeout: int | None):
    """Configure vault settings."""
    vault = VaultManager()
    require_vault(vault)

    from ._shared import unlock_vault
    try:
        (_payload, mek), _pw = unlock_vault(vault)
    except (InvalidTag, ValueError) as e:
        handle_vault_error(e)

    if idle_timeout is not None and idle_timeout < 1:
        console.print("[red]Idle timeout must be at least 1 minute.[/red]")
        raise SystemExit(1)

    def updater(p):
        if idle_timeout is not None:
            p.settings.idle_timeout_minutes = idle_timeout
        p.settings.validate()
        return p

    vault.update(updater, mek)
    console.print("[green]Settings updated.[/green]")
