import click
from rich.console import Console
from rich.markup import escape

from ..core.errors import SUPPORT_EMAIL
from ..core.vault import VaultManager

console = Console()

VAULT_MISSING_MSG = "No vault found. Run [green]'zenith-passkeys init'[/green] first."


def handle_vault_error(e: Exception) -> None:
    """Translate vault-layer failures into clean, actionable CLI errors."""
    from cryptography.exceptions import InvalidTag

    if isinstance(e, InvalidTag) or "password" in str(e).lower():
        console.print("[red]Wrong password.[/red]")
    elif "recovery" in str(e).lower():
        console.print("[red]Wrong recovery key or corrupted vault.[/red]")
    elif "corrupted" in str(e).lower() or "Invalid" in str(e):
        console.print(f"[red]Vault file is corrupted: {escape(str(e))}[/red]")
        console.print(f"[yellow]Contact {SUPPORT_EMAIL} with error code below if this persists.[/yellow]")
    else:
        console.print(f"[red]{escape(str(e))}[/red]")
    raise SystemExit(1)


def require_vault(vault: VaultManager) -> None:
    if not vault.exists():
        console.print(f"[red]{VAULT_MISSING_MSG}[/red]")
        raise SystemExit(1)


def unlock_vault(vault: VaultManager, prompt: str = "Master password") -> tuple:
    """Prompt, unlock, and convert any failure into a clean exit."""
    from cryptography.exceptions import InvalidTag

    password = click.prompt(prompt, hide_input=True)
    try:
        return vault.unlock(password), password
    except (InvalidTag, ValueError) as e:
        handle_vault_error(e)
