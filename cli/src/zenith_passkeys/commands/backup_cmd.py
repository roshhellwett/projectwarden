import os
import click
from rich.console import Console
from ..core.vault import VaultManager
from cryptography.exceptions import InvalidTag

console = Console()

@click.group()
def backup():
    """Manage cloud backups."""
    pass

@backup.command()
@click.option("--provider", required=True, type=click.Choice(["gdrive", "onedrive"]))
def push(provider: str):
    """Push vault to cloud backup."""
    vault = VaultManager()
    if not vault.exists():
        console.print("[red]No vault found. Run 'zenith-passkeys init' first.[/red]")
        raise SystemExit(1)

    password = click.prompt("Master password", hide_input=True)
    try:
        vault.unlock(password)
    except InvalidTag:
        console.print("[red]Wrong password.[/red]")
        raise SystemExit(1)

    with vault.lock:
        encrypted_blob = vault.vault_path.read_bytes()

    if provider == "gdrive":
        from ..backup.gdrive import GDriveProvider
        prov = GDriveProvider()
    else:
        from ..backup.onedrive import OneDriveProvider
        prov = OneDriveProvider()

    if not prov.is_authenticated():
        console.print("[yellow]Authenticating...[/yellow]")
        prov.authenticate()

    prov.upload(encrypted_blob, {"name": "zenith-vault-backup.enc"})
    console.print(f"[green]Backup pushed to {provider}.[/green]")

@backup.command()
@click.option("--provider", required=True, type=click.Choice(["gdrive", "onedrive"]))
def pull(provider: str):
    """Pull vault from cloud backup."""
    vault = VaultManager()
    if provider == "gdrive":
        from ..backup.gdrive import GDriveProvider
        prov = GDriveProvider()
    else:
        from ..backup.onedrive import OneDriveProvider
        prov = OneDriveProvider()

    if not prov.is_authenticated():
        console.print("[yellow]Authenticating...[/yellow]")
        prov.authenticate()

    blob, _ = prov.download()
    if not blob:
        console.print(f"[red]No backup found on {provider}.[/red]")
        raise SystemExit(1)

    if vault.exists():
        confirm = click.confirm("Local vault exists. Overwrite?", default=False)
        if not confirm:
            console.print("[yellow]Canceled.[/yellow]")
            return

    with vault.lock:
        vault.vault_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = vault.vault_path.with_suffix(".tmp")
        tmp.write_bytes(blob)
        os.replace(tmp, vault.vault_path)

    console.print(f"[green]Backup restored from {provider}.[/green]")
