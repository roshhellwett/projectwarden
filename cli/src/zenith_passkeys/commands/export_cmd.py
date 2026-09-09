import json
import os
from datetime import datetime, timezone

import click
from cryptography.exceptions import InvalidTag
from rich.console import Console

from ..core.crypto import (
    DEFAULT_KDF_ITERATIONS,
    DEFAULT_KDF_LANES,
    DEFAULT_KDF_MEMORY,
    derive_key,
    encrypt_aes_gcm,
)
from ..core.vault import VaultManager
from ._shared import handle_vault_error, require_vault

console = Console()


@click.command()
@click.option("--out", required=True, type=click.Path(), help="Output file path")
@click.option("--password", is_flag=True, help="Encrypt export with separate password")
def export(out: str, password: bool):
    """Export credentials to a file."""
    vault = VaultManager()
    require_vault(vault)

    from ._shared import unlock_vault
    try:
        (payload, _), _pw = unlock_vault(vault)
    except (InvalidTag, ValueError) as e:
        handle_vault_error(e)

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
        console.print("[bold yellow]WARNING: Export file is NOT encrypted.[/bold yellow]")
        console.print("[yellow]Anyone with access to this file can use your passkeys.[/yellow]")
        if not click.confirm("Continue with unencrypted export?", default=False):
            console.print("[yellow]Canceled.[/yellow]")
            return
        blob = json.dumps(export_data).encode("utf-8")

    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(out, flags, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(blob)
        f.flush()
        os.fsync(f.fileno())

    console.print(f"[green]Export written to {out}[/green]")
