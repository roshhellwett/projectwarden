import json
import click
from rich.console import Console
from rich.prompt import Prompt
from ..core.vault import VaultManager
from ..core.schema import Credential
from ..core.crypto import derive_key, decrypt_aes_gcm, DEFAULT_KDF_ITERATIONS, DEFAULT_KDF_MEMORY, DEFAULT_KDF_LANES
from cryptography.exceptions import InvalidTag

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
    added = 0
    for c_data in imported:
        cred = Credential(**c_data)
        existing = [e for e in payload.credentials if e.rp_id == cred.rp_id and e.credential_id == cred.credential_id]
        if existing:
            if skip_all:
                continue
            if overwrite_all:
                payload.credentials = [e for e in payload.credentials if not (e.rp_id == cred.rp_id and e.credential_id == cred.credential_id)]
                payload.credentials.append(cred)
                added += 1
                continue
            choice = Prompt.ask(
                f"[yellow]Credential {cred.rp_id}/{cred.username} exists. Skip/Overwrite/All-skip/All-overwrite?[/yellow]",
                choices=["s", "o", "as", "ao"],
                default="s",
            )
            if choice == "s":
                continue
            elif choice == "o":
                payload.credentials = [e for e in payload.credentials if not (e.rp_id == cred.rp_id and e.credential_id == cred.credential_id)]
                payload.credentials.append(cred)
                added += 1
            elif choice == "as":
                skip_all = True
                continue
            elif choice == "ao":
                overwrite_all = True
                payload.credentials = [e for e in payload.credentials if not (e.rp_id == cred.rp_id and e.credential_id == cred.credential_id)]
                payload.credentials.append(cred)
                added += 1
        else:
            payload.credentials.append(cred)
            added += 1

    vault.save(payload, mek)
    console.print(f"[green]Imported {added} credential(s).[/green]")
