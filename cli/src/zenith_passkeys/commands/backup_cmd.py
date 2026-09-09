import hashlib
import os
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
import uuid

import click
from cryptography.exceptions import InvalidTag
from filelock import FileLock
from rich.console import Console
from rich.panel import Panel

from ..core.crypto import VaultHeader
from ..core.vault import VaultManager
from ._shared import handle_vault_error, require_vault

console = Console()


@click.group()
def backup():
    """Manage local encrypted vault backups (100% offline & air-gapped).

    Built and managed by Zenith Open Source Projects.
    """


@backup.command(name="create")
@click.argument("output_path", required=False, type=click.Path())
def create(output_path: str | None):
    """Create an encrypted vault backup snapshot.

    Saves directly to your chosen medium (USB pendrive, external HDD, or local folder).
    If OUTPUT_PATH is omitted, a timestamped file is created in the current directory.
    """
    vault = VaultManager()
    require_vault(vault)

    from ._shared import unlock_vault
    try:
        (payload, _mek), _pw = unlock_vault(vault)
    except (InvalidTag, ValueError) as e:
        handle_vault_error(e)

    if output_path:
        target = Path(output_path).resolve()
        if target.is_dir():
            ts = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M%S")
            target = target / f"zenith-vault-backup-{ts}.enc"
    else:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M%S")
        target = Path.cwd() / f"zenith-vault-backup-{ts}.enc"

    target.parent.mkdir(parents=True, exist_ok=True)

    with vault.lock:
        blob = vault.vault_path.read_bytes()

    # Transactional atomic write to target destination
    tmp_target = target.parent / f"{target.name}.tmp.{uuid.uuid4().hex[:8]}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(str(tmp_target), flags, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(blob)
        f.flush()
        os.fsync(f.fileno())

    os.replace(tmp_target, target)

    sha256 = hashlib.sha256(blob).hexdigest()
    cred_count = len(payload.credentials)

    console.print()
    console.print(Panel(
        f"[bold green]Vault backup successfully created![/bold green]\n\n"
        f"[bold]Destination:[/bold] [cyan]{target}[/cyan]\n"
        f"[bold]Credentials:[/bold] {cred_count}\n"
        f"[bold]File Size:[/bold] {len(blob):,} bytes\n"
        f"[bold]SHA-256:[/bold] [dim]{sha256}[/dim]\n\n"
        f"[dim]Encrypted with Argon2id + AES-256-GCM. 100% offline and air-gapped.\n"
        f"Safe to store on a USB pendrive, external drive, or cold storage.[/dim]",
        title="Zenith Passkeys Backup",
        border_style="green",
    ))


@backup.command(name="restore")
@click.argument("file_path", required=True, type=click.Path(exists=True, dir_okay=False))
def restore(file_path: str):
    """Restore vault from an encrypted backup file.

    Verifies backup integrity and master password before touching the local vault.
    """
    source = Path(file_path).resolve()
    blob = source.read_bytes()

    if not blob:
        console.print(f"[red]Backup file '{source}' is empty.[/red]")
        raise SystemExit(1)

    if len(blob) > 50 * 1024 * 1024:
        console.print("[red]Backup file is too large (max 50MB).[/red]")
        raise SystemExit(1)

    # ── Pre-flight Header Validation ──
    try:
        header = VaultHeader.from_bytes(blob)
        if len(blob) < header.size() + 16:
            raise ValueError("Invalid payload size")
    except Exception as e:
        console.print(f"[red]File is corrupted or not a valid Zenith vault: {e}[/red]")
        raise SystemExit(1) from None

    # ── Pre-flight In-Memory Test Decryption ──
    confirm_pw = click.prompt("Master password of the BACKUP vault", hide_input=True)
    probe = VaultManager(vault_path=None)
    with tempfile.TemporaryDirectory() as td:
        staged_path = Path(td) / "vault.enc"
        staged_path.write_bytes(blob)
        probe.vault_path = staged_path
        probe.lock = FileLock(str(staged_path) + ".lock", timeout=10)
        try:
            restored_payload, _ = probe.unlock(confirm_pw)
        except (InvalidTag, ValueError):
            console.print("[red]That password does not unlock this backup vault. Local vault NOT touched.[/red]")
            raise SystemExit(1) from None

    vault = VaultManager()

    # ── Overwrite Confirmation & Rollback Safety Snapshot ──
    if vault.exists():
        console.print("[yellow]Current local vault contains credentials.[/yellow]")
        if not click.confirm("Overwrite local vault with verified backup?", default=False):
            console.print("[yellow]Restore canceled. Local vault unchanged.[/yellow]")
            return
        # Automatic local rollback snapshot
        backup_snapshot = vault.vault_path.with_suffix(".bak")
        shutil.copy2(vault.vault_path, backup_snapshot)

    # ── Atomic Install ──
    with vault.lock:
        vault.vault_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = vault.vault_path.with_suffix(f".tmp.{uuid.uuid4().hex[:8]}")
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(blob)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, vault.vault_path)

    cred_count = len(restored_payload.credentials)
    console.print()
    console.print(Panel(
        f"[bold green]Vault successfully restored![/bold green]\n\n"
        f"[bold]Source:[/bold] [cyan]{source}[/cyan]\n"
        f"[bold]Active Vault:[/bold] {vault.vault_path}\n"
        f"[bold]Restored Credentials:[/bold] {cred_count}\n\n"
        f"[dim]Local vault is ready for use with the browser extension.[/dim]",
        title="Restore Completed",
        border_style="green",
    ))
