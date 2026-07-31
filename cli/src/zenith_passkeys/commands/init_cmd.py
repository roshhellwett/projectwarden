import os
import click
from rich.console import Console
from rich.panel import Panel
from ..core.vault import VaultManager
from ..core.crypto import VaultHeader, HEADER_SIZE, DEFAULT_KDF_ITERATIONS, DEFAULT_KDF_MEMORY, DEFAULT_KDF_LANES, derive_key, encrypt_aes_gcm
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
            dk_new = derive_key(new_password.encode(), header.kdf_salt, header.kdf_iterations, header.kdf_memory, header.kdf_lanes)
            new_nonce = os.urandom(12)
            new_wrapped = encrypt_aes_gcm(mek, dk_new, new_nonce)
            header.pw_wrapped_nonce = new_nonce
            header.pw_wrapped_mek = new_wrapped
            payload_ct = raw[HEADER_SIZE:]
            tmp = vault.vault_path.with_suffix(".tmp")
            tmp.write_bytes(header.to_bytes() + payload_ct)
            os.replace(tmp, vault.vault_path)
        console.print("[green]Vault recovered successfully.[/green]")
        register_native_host()
        return

    password = click.prompt("Master password", hide_input=True, confirmation_prompt=True)
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
