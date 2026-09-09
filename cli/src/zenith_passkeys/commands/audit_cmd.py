import json
from datetime import datetime, timezone

import click
from cryptography.exceptions import InvalidTag
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from ..core.vault import VaultManager
from ._shared import handle_vault_error, require_vault

console = Console()


@click.command()
@click.option("--unused-days", default=90, type=int, help="Days of inactivity threshold")
@click.option("--dns", is_flag=True, help="Also check domain DNS resolution (makes network requests)")
@click.option("--json-output", "json_flag", is_flag=True, help="Output as JSON")
def audit(unused_days: int, dns: bool, json_flag: bool):
    """Audit vault for security issues (offline by default)."""
    vault = VaultManager()
    require_vault(vault)

    from ._shared import unlock_vault
    try:
        (payload, _), _pw = unlock_vault(vault)
    except (InvalidTag, ValueError) as e:
        handle_vault_error(e)

    issues = []
    now = datetime.now(timezone.utc)

    for c in payload.credentials:
        if c.last_used_at:
            try:
                last = datetime.fromisoformat(c.last_used_at)
            except ValueError:
                continue
            if (now - last).days >= unused_days:
                issues.append({
                    "type": "stale",
                    "severity": "low",
                    "rp_id": c.rp_id,
                    "username": c.username,
                    "detail": f"Not used in {(now - last).days} days",
                })

    seen = {}
    for c in payload.credentials:
        key = (c.rp_id, c.username)
        if key in seen:
            issues.append({
                "type": "duplicate",
                "severity": "medium",
                "rp_id": c.rp_id,
                "username": c.username,
                "detail": "Multiple credentials for same rpId+username",
            })
        seen[key] = True

    # DNS resolution is OPT-IN: it sends every stored domain to the system
    # resolver, which leaks the user's site list. Default is offline.
    if dns:
        import socket
        for domain in {c.rp_id for c in payload.credentials}:
            try:
                socket.getaddrinfo(domain, 443, socket.AF_INET, socket.SOCK_STREAM)
            except socket.gaierror:
                issues.append({
                    "type": "unresolvable",
                    "severity": "high",
                    "rp_id": domain,
                    "username": "",
                    "detail": f"Cannot resolve {domain}",
                })

    if json_flag:
        console.print_json(json.dumps(issues, indent=2))
    else:
        if not issues:
            console.print("[green]No issues found. Vault looks good.[/green]")
            raise SystemExit(0)

        table = Table(title=f"Audit Issues ({len(issues)})")
        table.add_column("Severity", style="yellow")
        table.add_column("Type", style="cyan")
        table.add_column("Domain", style="white")
        table.add_column("Detail", style="white")
        for issue in issues:
            table.add_row(escape(issue["severity"]), escape(issue["type"]), escape(issue["rp_id"]), escape(issue["detail"]))
        console.print(table)
        raise SystemExit(1)
