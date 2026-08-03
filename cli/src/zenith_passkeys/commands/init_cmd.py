import os
import click
from rich.console import Console
from rich.panel import Panel
from ..core.vault import VaultManager
from ..core.crypto import VaultHeader, HEADER_SIZE_V1, HEADER_SIZE_V2, DEFAULT_KDF_ITERATIONS, DEFAULT_KDF_MEMORY, DEFAULT_KDF_LANES, derive_key, encrypt_aes_gcm, decrypt_aes_gcm
from ..core.recovery import parse_recovery_key
from ..native_host.manifest import register_native_host
from cryptography.exceptions import InvalidTag

console = Console()

@click.command()
@click.option("--recover", is_flag=True, help="Recover vault using recovery key")
def init(recover: bool):
    """Initialize or recover a vault."""
    vault = VaultManager()

    if vault.exists() and not recover:
        console.print("Vault exists. Registering native host only.")
        register_native_host()
        return

    if recover:
        if not vault.exists():
            console.print("[red]No vault found to recover.[/red]")
            raise SystemExit(1)
        recovery_display = click.prompt("Recovery key", hide_input=True)
        try:
            recovery_raw = parse_recovery_key(recovery_display)
        except ValueError:
            console.print("[red]Invalid recovery key format.[/red]")
            raise SystemExit(1)
        try:
            _, mek = vault.unlock_with_recovery(recovery_raw)
        except InvalidTag:
            console.print("[red]Wrong recovery key.[/red]")
            raise SystemExit(1)
        new_password = click.prompt("New master password", hide_input=True, confirmation_prompt=True)
        with vault.lock:
            raw = vault.vault_path.read_bytes()
            header = VaultHeader.from_bytes(raw)
            aad = header.aad() if header.version >= 2 else None
            dk_new = derive_key(new_password.encode(), header.pw_salt, header.kdf_iterations, header.kdf_memory, header.kdf_lanes)
            
            old_aad = aad
            # Rotate pw_salt if V2
            if header.version >= 2:
                header.pw_salt = os.urandom(16)
                aad = header.aad()
                dk_new = derive_key(new_password.encode(), header.pw_salt, header.kdf_iterations, header.kdf_memory, header.kdf_lanes)

            new_nonce = os.urandom(12)
            new_wrapped = encrypt_aes_gcm(mek, dk_new, new_nonce, aad)
            header.pw_wrapped_nonce = new_nonce
            header.pw_wrapped_mek = new_wrapped
            
            if header.version >= 2:
                payload_ct = raw[header.size():]
                # AAD for payload might have changed due to pw_salt change
                payload_json = decrypt_aes_gcm(payload_ct, mek, header.payload_nonce, old_aad)
                new_payload_nonce = os.urandom(12)
                payload_ct = encrypt_aes_gcm(payload_json, mek, new_payload_nonce, aad)
                header.payload_nonce = new_payload_nonce
            else:
                payload_ct = raw[header.size():]
            
            tmp = vault.vault_path.with_suffix(".tmp")
            fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(header.to_bytes() + payload_ct)
                f.flush()
                os.fsync(f.fileno())
            os.replace(str(tmp), str(vault.vault_path))
        console.print("[green]Vault recovered successfully.[/green]")
        register_native_host()
        return

    password = click.prompt("Master password", hide_input=True, confirmation_prompt=True)
    if len(password) < 8:
        console.print("[red]Password must be at least 8 characters.[/red]")
        raise SystemExit(1)
    display_recovery, _ = vault.create(password)
    console.print()
    console.print(Panel(
        f"[bold yellow]!!! SAVE THIS RECOVERY KEY !!![/bold yellow]\n\n"
        f"[bold]{display_recovery}[/bold]\n\n"
        f"[red]If you lose your password and this recovery key, "
        f"your passkeys are gone forever.[/red]",
        title="Recovery Key",
        border_style="yellow",
    ))
    console.print()
    console.print("[green]Vault created successfully.[/green]")
    register_native_host()
