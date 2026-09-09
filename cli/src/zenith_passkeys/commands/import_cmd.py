import json
import os

import click
from cryptography.exceptions import InvalidTag
from rich.console import Console
from rich.markup import escape
from rich.prompt import Prompt

from ..core.crypto import (
    DEFAULT_KDF_ITERATIONS,
    DEFAULT_KDF_LANES,
    DEFAULT_KDF_MEMORY,
    decrypt_aes_gcm,
    derive_key,
)
from ..core.schema import Credential
from ..core.vault import VaultManager
from ._shared import handle_vault_error, require_vault

console = Console()

REQUIRED_FIELDS = {"rp_id", "credential_id", "private_key", "public_key", "username"}


def _validate_credential_entry(c_data: dict) -> Credential:
    """Validate one imported credential; raise ValueError with a clean message."""
    if not isinstance(c_data, dict):
        raise ValueError("credential entry is not an object")  # noqa: TRY004 - user-input validation
    missing = REQUIRED_FIELDS - set(c_data.keys())
    if missing:
        raise ValueError(f"credential missing fields: {', '.join(sorted(missing))}")

    for f in ("rp_id", "credential_id", "private_key", "public_key", "username"):
        v = c_data[f]
        if not isinstance(v, str) or not v:
            raise ValueError(f"field '{f}' must be a non-empty string")
        if len(v) > 4096:
            raise ValueError(f"field '{f}' is too large")

    user_handle = c_data.get("user_handle", "")
    if not isinstance(user_handle, str):
        raise ValueError("field 'user_handle' must be a string")
    if len(user_handle) > 4096:
        raise ValueError("field 'user_handle' is too large")
    c_data = dict(c_data)
    c_data["user_handle"] = user_handle

    counter = c_data.get("counter", 0)
    if not isinstance(counter, int) or counter < 0 or counter > 2**32:
        raise ValueError("'counter' must be a non-negative integer")

    algorithm = c_data.get("algorithm", -7)
    if algorithm not in (-7, -257):
        raise ValueError("'algorithm' must be -7 (ES256) or -257 (RS256)")

    return Credential(**c_data)


@click.command()
@click.argument("file", type=click.Path(exists=True))
def import_vault(file: str):
    """Import credentials from an export file."""
    vault = VaultManager()
    require_vault(vault)

    from ._shared import unlock_vault
    try:
        (payload, mek), _pw = unlock_vault(vault)
    except (InvalidTag, ValueError) as e:
        handle_vault_error(e)

    if os.path.getsize(file) > 50 * 1024 * 1024:
        console.print("[red]Import file is too large (max 50MB).[/red]")
        raise SystemExit(1)

    with open(file, "rb") as f:
        blob = f.read()

    import_data = None
    if blob.startswith(b"{"):
        try:
            import_data = json.loads(blob.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            console.print(f"[red]Import file is not valid JSON: {escape(str(e))}[/red]")
            raise SystemExit(1) from None
    else:
        if len(blob) < 28:
            console.print("[red]Import file is corrupted or not a valid export.[/red]")
            raise SystemExit(1)
        salt = blob[:16]
        nonce = blob[16:28]
        ct = blob[28:]
        import_pw = click.prompt("Import password", hide_input=True)
        dk = derive_key(import_pw.encode(), salt, DEFAULT_KDF_ITERATIONS, DEFAULT_KDF_MEMORY, DEFAULT_KDF_LANES)
        try:
            plain = decrypt_aes_gcm(ct, dk, nonce)
        except InvalidTag:
            console.print("[red]Wrong import password.[/red]")
            raise SystemExit(1) from None
        import_data = json.loads(plain.decode("utf-8"))

    if not isinstance(import_data, dict) or "credentials" not in import_data:
        console.print("[red]Import file is corrupted or not a valid export.[/red]")
        raise SystemExit(1)

    imported = import_data.get("credentials", [])
    if not isinstance(imported, list):
        console.print("[red]Import file is corrupted: 'credentials' must be a list.[/red]")
        raise SystemExit(1)
    if not imported:
        console.print("[yellow]No credentials in import file.[/yellow]")
        return

    # Validate every entry BEFORE writing anything to the vault.
    parsed: list[Credential] = []
    for idx, c_data in enumerate(imported):
        try:
            parsed.append(_validate_credential_entry(c_data))
        except ValueError as e:
            console.print(f"[red]Invalid credential #{idx + 1}: {escape(str(e))}[/red]")
            console.print("[yellow]Nothing was imported. Fix the file and try again.[/yellow]")
            raise SystemExit(1) from None

    console.print(f"Found {len(parsed)} credential(s) to import.")
    skip_all = False
    overwrite_all = False
    to_add = []
    to_overwrite = []

    for cred in parsed:
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
