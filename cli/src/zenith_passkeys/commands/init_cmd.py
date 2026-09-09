import click
from rich.console import Console
from rich.panel import Panel

from ..core.errors import SUPPORT_EMAIL
from ..core.recovery import parse_recovery_key
from ..core.vault import VaultManager
from ..native_host.manifest import register_native_host

console = Console()


@click.command()
@click.option("--recover", is_flag=True, help="Recover vault using recovery key")
@click.option("--extension-id", default=None, help="Chrome/Edge extension ID to allow in the native host manifest")
def init(recover: bool, extension_id: str | None):
    """Initialize or recover a vault."""
    vault = VaultManager()

    if vault.exists() and not recover:
        console.print("Vault exists. Registering native host only.")
        errors = register_native_host(extension_id)
        if errors:
            for e in errors:
                console.print(f"[yellow]Warning: {e}[/yellow]")
            console.print(f"[yellow]Contact {SUPPORT_EMAIL} if the browser cannot connect.[/yellow]")
        else:
            console.print("[green]Native host registered.[/green]")
        return

    if recover:
        if not vault.exists():
            console.print("[red]No vault found to recover.[/red]")
            raise SystemExit(1)
        recovery_display = click.prompt("Recovery key", hide_input=True)
        try:
            recovery_raw = parse_recovery_key(recovery_display)
        except ValueError:
            console.print("[red]Invalid recovery key format.[/red]")
            raise SystemExit(1)
        new_password = click.prompt("New master password", hide_input=True, confirmation_prompt=True)
        try:
            # set_password_with_recovery re-wraps BOTH slots so the recovery
            # key remains usable afterwards (see audit F-001).
            vault.set_password_with_recovery(recovery_raw, new_password)
        except ValueError as e:
            console.print(f"[red]{e}[/red]")
            raise SystemExit(1)
        console.print("[green]Vault recovered successfully.[/green]")
        console.print("[dim]Your recovery key is unchanged — it still works.[/dim]")
        errors = register_native_host(extension_id)
        for e in errors:
            console.print(f"[yellow]Warning: {e}[/yellow]")
        return

    if vault.exists():
        console.print("[red]Vault already exists. Use 'zenith-passkeys init --recover' to recover.[/red]")
        raise SystemExit(1)

    password = click.prompt("Master password", hide_input=True, confirmation_prompt=True)
    if len(password) < 8:
        console.print("[red]Password must be at least 8 characters.[/red]")
        raise SystemExit(1)
    display_recovery, _ = vault.create(password)
    console.print()
    console.print(Panel(
        f"[bold yellow]!!! SAVE THIS RECOVERY KEY !!![/bold yellow]\n\n"
        f"[bold]{display_recovery}[/bold]\n\n"
        f"[red]If you lose your password and this key, "
        f"your passkeys are gone forever.[/red]",
        title="Recovery Key",
        border_style="yellow",
    ))
    console.print()
    console.print("[green]Vault created successfully.[/green]")
    register_native_host(extension_id)
