import getpass
import json
from datetime import datetime, timezone

import click
from cryptography.exceptions import InvalidTag

from ..core.vault import VaultManager
from ._shared import handle_vault_error

console = None  # logs uses plain click.echo; keep output JSON-safe


@click.command()
@click.option('--json-output', is_flag=True, help="Output logs as JSON")
def logs(json_output):
    """View the internal vault action log for diagnostics."""
    manager = VaultManager()
    if not manager.exists():
        click.secho("No vault found. Run 'zenith-passkeys init' first.", fg="red")
        return

    password = getpass.getpass("Master password: ")
    try:
        payload, _ = manager.unlock(password)

        if json_output:
            out = []
            for entry in payload.action_log:
                out.append({
                    "timestamp": entry.timestamp,
                    "action": entry.action,
                    "status": entry.status,
                    "details": entry.details,
                })
            click.echo(json.dumps(out, indent=2))
        else:
            if not payload.action_log:
                click.echo("No logs found.")
                return
            for entry in payload.action_log:
                dt = datetime.fromtimestamp(entry.timestamp, tz=timezone.utc).astimezone().strftime('%Y-%m-%d %H:%M:%S')
                color = "green" if entry.status == "success" else "red"
                status = click.style(f"[{entry.status.upper()}]", fg=color)
                click.echo(f"{dt} {status} {entry.action.upper()}: {entry.details}")
    except (InvalidTag, ValueError) as e:
        handle_vault_error(e)
