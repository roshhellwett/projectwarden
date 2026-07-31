import click
from rich.console import Console
from ..core.vault import VaultManager
from cryptography.exceptions import InvalidTag

console = Console()

@click.command()
@click.option("--use-keyring", is_flag=True, help="Store master password in OS keyring")
@click.option("--idle-timeout", type=int, default=None, help="Idle timeout in minutes")
def config(use_keyring: bool, idle_timeout: int | None):
    """Configure vault settings."""
    vault = VaultManager()
    if not vault.exists():
        console.print("[red]No vault found. Run 'zenith-passkeys init' first.[/red]")
        raise SystemExit(1)

    password = click.prompt("Master password", hide_input=True)
    try:
        payload, mek = vault.unlock(password)
    except InvalidTag:
        console.print("[red]Wrong password.[/red]")
        raise SystemExit(1)

    if use_keyring:
        import keyring
        keyring.set_password("zenith-passkeys", "master", password)
        payload.settings.use_keyring = True
        console.print("[green]Password stored in OS keyring.[/green]")

    if idle_timeout is not None:
        payload.settings.idle_timeout_minutes = idle_timeout

    vault.save(payload, mek)
    console.print("[green]Settings updated.[/green]")
