import click
from rich.console import Console

from ..core.vault import VaultManager

console = Console()


@click.command(name="rotate-recovery-key")
@click.option("--password", default=None, help="Master password")
def rotate_recovery(password: str | None):
    """Generate and display a new active Emergency Recovery Key.

    Requires master password to verify identity. Re-wraps the vault
    recovery slot and invalidates any previous recovery key.
    """
    vault = VaultManager()

    if not vault.exists():
        console.print("[red]No vault found. Run 'zenith-passkeys init' first.[/red]")
        raise SystemExit(1)

    if not password:
        password = click.prompt("Master password", hide_input=True)

    try:
        _, mek = vault.unlock(password)
    except ValueError as e:
        console.print(f"[red]Authentication failed: {e}[/red]")
        raise SystemExit(1)

    try:
        new_key = vault.rotate_recovery_key(mek)
    except Exception as e:
        console.print(f"[red]Failed to rotate recovery key: {e}[/red]")
        raise SystemExit(1)

    console.print("\n[bold green]Emergency Recovery Key rotated successfully![/bold green]")
    console.print("\nYour new Emergency Recovery Key is:")
    console.print(f"  [bold cyan]{new_key}[/bold cyan]\n")
    console.print("[yellow]Save this key in a secure physical location or notebook.[/yellow]")
    console.print("[dim]Any previous recovery key has been permanently invalidated.[/dim]\n")
