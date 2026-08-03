import json
import os
import click
from rich.console import Console
from rich.prompt import Prompt
from ..core.vault import VaultManager
from ..core.schema import Credential
from ..core.crypto import derive_key, decrypt_aes_gcm, DEFAULT_KDF_ITERATIONS, DEFAULT_KDF_MEMORY, DEFAULT_KDF_LANES
from cryptography.exceptions import InvalidTag
from rich.markup import escape

console = Console()

@click.command()
@click.argument("file", type=click.Path(exists=True))
def import_vault(file: str):
    """Import credentials from an export file."""
    vault = VaultManager()
    if not vault.exists():
        console.print("[red]No vault found. Run 'zenith-passkeys init' first.[/red]")
        raise SystemExit(1)

    master_pw = click.prompt("Master password", hide_input=True)
    try:
        payload, mek = vault.unlock(master_pw)
    except InvalidTag:
        console.print("[red]Wrong password.[/red]")
        raise SystemExit(1)

    if os.path.getsize(file) > 50 * 1024 * 1024:
        console.print("[red]Import file is too large (max 50MB).[/red]")
        raise SystemExit(1)
        
    with open(file, "rb") as f:
        blob = f.read()

    import_data = None
    if blob.startswith(b"{"):
        import_data = json.loads(blob.decode("utf-8"))
    else:
        salt = blob[:16]
        nonce = blob[16:28]
        ct = blob[28:]
        import_pw = click.prompt("Import password", hide_input=True)
        dk = derive_key(import_pw.encode(), salt, DEFAULT_KDF_ITERATIONS, DEFAULT_KDF_MEMORY, DEFAULT_KDF_LANES)
        try:
            plain = decrypt_aes_gcm(ct, dk, nonce)
            import_data = json.loads(plain.decode("utf-8"))
        except InvalidTag:
            console.print("[red]Wrong import password.[/red]")
            raise SystemExit(1)

    imported = import_data.get("credentials", [])
    if not imported:
        console.print("[yellow]No credentials in import file.[/yellow]")
        return

    console.print(f"Found {len(imported)} credential(s) to import.")
    skip_all = False
    overwrite_all = False
    to_add = []
    to_overwrite = []
    
    for c_data in imported:
        cred = Credential(**c_data)
        existing = [e for e in payload.credentials if e.rp_id == cred.rp_id and e.credential_id == cred.credential_id]
        if existing:
            if skip_all:
                continue
            if overwrite_all:
                to_overwrite.append(cred)
                continue
            choice = Prompt.ask(
                f"[yellow]Credential {escape(cred.rp_id)}/{escape(cred.username)} exists. Skip/Overwrite/All-skip/All-overwrite?[/yellow]",
                choices=["s", "o", "as", "ao"],
                default="s",
            )
            if choice == "s":
                continue
            elif choice == "o":
                to_overwrite.append(cred)
            elif choice == "as":
                skip_all = True
            elif choice == "ao":
                overwrite_all = True
                to_overwrite.append(cred)
        else:
            to_add.append(cred)

    def updater(p):
        for cred in to_overwrite:
            p.credentials = [e for e in p.credentials if not (e.rp_id == cred.rp_id and e.credential_id == cred.credential_id)]
            p.credentials.append(cred)
        for cred in to_add:
            if not any(e.rp_id == cred.rp_id and e.credential_id == cred.credential_id for e in p.credentials):
                p.credentials.append(cred)
        return p

    vault.update(updater, mek)
    console.print(f"[green]Imported {len(to_add) + len(to_overwrite)} credential(s).[/green]")
