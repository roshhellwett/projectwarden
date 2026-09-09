import click
from cryptography.exceptions import InvalidTag
from rich.console import Console
from rich.markup import escape

from ..core.credentials import delete_credential
from ..core.vault import VaultManager
from ._shared import handle_vault_error, require_vault

console = Console()


@click.command()
@click.argument("domain")
@click.option("--credential-id", default=None, help="Specific credential ID to delete")
@click.option("--force", is_flag=True, help="Skip confirmation prompt")
def delete(domain: str, credential_id: str | None, force: bool):
    """Delete a passkey credential by domain."""
    vault = VaultManager()
    require_vault(vault)

    from ._shared import unlock_vault
    try:
        (payload, mek), _pw = unlock_vault(vault)
    except (InvalidTag, ValueError) as e:
        handle_vault_error(e)

    # Find matching credentials
    matches = [c for c in payload.credentials if c.rp_id == domain]
    if credential_id:
        matches = [c for c in matches if c.credential_id == credential_id]

    if not matches:
        console.print(f"[yellow]No credentials found for {escape(domain)}.[/yellow]")
        raise SystemExit(1)

    if len(matches) > 1 and not credential_id:
        console.print(f"[yellow]Multiple credentials found for {escape(domain)}:[/yellow]")
        for i, c in enumerate(matches):
            console.print(f"  [{i+1}] {escape(c.username)} (ID: {c.credential_id[:12]}...)")
        console.print("[yellow]Use --credential-id to specify which one to delete.[/yellow]")
        raise SystemExit(1)

    target = matches[0]

    if not force:
        console.print("\n[bold]About to delete:[/bold]")
        console.print(f"  Domain:   {escape(target.rp_id)}")
        console.print(f"  Username: {escape(target.username)}")
        console.print(f"  ID:       {target.credential_id[:20]}...")
        console.print()
        if not click.confirm("[red]This action cannot be undone. Continue?[/red]", default=False):
            console.print("[yellow]Canceled.[/yellow]")
            return

    def updater(p):
        return delete_credential(p, target.credential_id)

    vault.update(updater, mek)
    console.print(f"[green]✓ Credential for {escape(target.rp_id)} deleted.[/green]")
