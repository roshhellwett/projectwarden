import json
from datetime import datetime, timezone

import click
from cryptography.exceptions import InvalidTag
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from ..core.vault import VaultManager
from ._shared import handle_vault_error, require_vault

console = Console()


@click.command()
@click.option("--json-output", "json_flag", is_flag=True, help="Output as JSON")
@click.option("--domain", default=None, help="Filter by domain")
@click.option("--unused-days", default=None, type=int, help="Show credentials unused for N days")
def list_credentials(json_flag: bool, domain: str | None, unused_days: int | None):
    """List stored credentials."""
    vault = VaultManager()
    require_vault(vault)

    from ._shared import unlock_vault
    try:
        (payload, _), _pw = unlock_vault(vault)
    except (InvalidTag, ValueError) as e:
        handle_vault_error(e)

    creds = payload.credentials
    if domain:
        creds = [c for c in creds if c.rp_id == domain]
    if unused_days is not None:
        cutoff = datetime.now(timezone.utc)
        creds = [
            c for c in creds
            if c.last_used_at is None
            or (cutoff - datetime.fromisoformat(c.last_used_at)).days >= unused_days
        ]

    if json_flag:
        console.print_json(json.dumps([{
            "rpId": c.rp_id,
            "credentialId": c.credential_id,
            "username": c.username,
            "createdAt": c.created_at,
            "lastUsedAt": c.last_used_at,
            "counter": c.counter,
        } for c in creds]))
        return

    if not creds:
        console.print("[yellow]No credentials found.[/yellow]")
        return

    table = Table(title=f"Credentials ({len(creds)})")
    table.add_column("Domain", style="cyan")
    table.add_column("Username", style="green")
    table.add_column("Created", style="white")
    table.add_column("Last Used", style="white")
    table.add_column("Uses", style="yellow")

    for c in creds:
        last = c.last_used_at or "—"
        if c.last_used_at:
            try:
                dt = datetime.fromisoformat(c.last_used_at)
                last = dt.strftime("%Y-%m-%d")
            except ValueError:
                pass
        table.add_row(escape(c.rp_id), escape(c.username), escape(c.created_at[:10] if c.created_at else "—"), escape(last), str(c.counter))

    console.print(table)
