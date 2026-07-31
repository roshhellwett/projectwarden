import json
import os
from datetime import datetime, timezone
import click
from rich.console import Console
from ..core.vault import VaultManager
from ..core.crypto import derive_key, encrypt_aes_gcm, DEFAULT_KDF_ITERATIONS, DEFAULT_KDF_MEMORY, DEFAULT_KDF_LANES
from cryptography.exceptions import InvalidTag

console = Console()

@click.command()
@click.option("--out", required=True, type=click.Path(), help="Output file path")
@click.option("--password", is_flag=True, help="Encrypt export with separate password")
def export(out: str, password: bool):
    """Export credentials to a file."""
    vault = VaultManager()
    if not vault.exists():
        console.print("[red]No vault found. Run 'zenith-passkeys init' first.[/red]")
        raise SystemExit(1)

    master_pw = click.prompt("Master password", hide_input=True)
    try:
        payload, _ = vault.unlock(master_pw)
    except InvalidTag:
        console.print("[red]Wrong password.[/red]")
        raise SystemExit(1)

    export_pw = None
    if password:
        export_pw = click.prompt("Export password", hide_input=True, confirmation_prompt=True)

    export_data = {
        "version": 1,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "credentials": [
            {
                "rp_id": c.rp_id,
                "credential_id": c.credential_id,
                "private_key": c.private_key,
                "public_key": c.public_key,
                "user_handle": c.user_handle,
                "username": c.username,
                "counter": c.counter,
                "algorithm": c.algorithm,
            }
            for c in payload.credentials
        ],
    }

    if export_pw:
        salt = os.urandom(16)
        dk = derive_key(export_pw.encode(), salt, DEFAULT_KDF_ITERATIONS, DEFAULT_KDF_MEMORY, DEFAULT_KDF_LANES)
        nonce = os.urandom(12)
        ct = encrypt_aes_gcm(json.dumps(export_data).encode("utf-8"), dk, nonce)
        blob = salt + nonce + ct
    else:
        console.print("[bold yellow]⚠️  WARNING: Export file is NOT encrypted.[/bold yellow]")
        console.print("[yellow]Anyone with access to this file can use your passkeys.[/yellow]")
        if not click.confirm("Continue with unencrypted export?", default=False):
            console.print("[yellow]Canceled.[/yellow]")
            return
        blob = json.dumps(export_data).encode("utf-8")

    with open(out, "wb") as f:
        f.write(blob)

    console.print(f"[green]Export written to {out}[/green]")
