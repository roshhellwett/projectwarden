import click
from rich.console import Console

from ..core.recovery import parse_recovery_key
from ..core.vault import VaultManager

console = Console()


@click.command(name="recover")
@click.option("--key", "recovery_key", default=None, help="Emergency recovery key (XXXX-XXXX-...)")
def recover(recovery_key: str | None):
    """Recover vault using your 32-character Emergency Recovery Key.

    Allows resetting the master password if you forgot it.
    Your recovery key remains valid and unchanged after recovery.
    """
    vault = VaultManager()

    if not vault.exists():
        console.print("[red]No vault found to recover. Run 'zenith-passkeys init' first.[/red]")
        raise SystemExit(1)

    if not recovery_key:
        recovery_key = click.prompt("Emergency Recovery Key", hide_input=False)

    recovery_key = (recovery_key or "").strip()
    if not recovery_key:
        console.print("[red]Emergency recovery key cannot be empty.[/red]")
        raise SystemExit(1)

    try:
        recovery_raw = parse_recovery_key(recovery_key)
    except ValueError as e:
        console.print(f"[red]Invalid recovery key format: {e}[/red]")
        raise SystemExit(1)

    new_password = click.prompt("New master password", hide_input=True, confirmation_prompt=True)
    if len(new_password) < 8:
        console.print("[red]Password must be at least 8 characters.[/red]")
        raise SystemExit(1)

    try:
        # set_password_with_recovery re-wraps BOTH slots so the recovery
        # key remains usable afterwards.
        vault.set_password_with_recovery(recovery_raw, new_password)
    except ValueError as e:
        console.print(f"[red]Recovery failed: {e}[/red]")
        raise SystemExit(1)

    console.print("\n[bold green]Vault recovered successfully![/bold green]")
    console.print("[green]Your master encryption key has been re-wrapped under your new password.[/green]")
    console.print("[dim]Note: Your recovery key remains unchanged and active for future emergency use.[/dim]\n")
