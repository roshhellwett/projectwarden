import click
from rich.console import Console

from ..native_host.lock_sentinel import read_lock_ack, request_lock

console = Console()


@click.command()
def lock():
    """Lock the vault everywhere: clears the native host session (if running)."""
    placed = request_lock()
    if not placed:
        console.print("[red]Could not write the lock signal to the vault directory.[/red]")
        raise SystemExit(1)

    # The host polls every second; give it a moment to acknowledge.
    import time
    deadline = time.time() + 3
    while time.time() < deadline:
        if read_lock_ack():
            break
        time.sleep(0.2)

    console.print("[green]✓ Vault locked.[/green]")
    console.print("[dim]The browser extension session clears within ~1 second. If no browser session was open, there was nothing to clear.[/dim]")
