import json
import socket
from datetime import datetime, timezone
import click
from rich.console import Console
from rich.table import Table
from ..core.vault import VaultManager
from cryptography.exceptions import InvalidTag

console = Console()

@click.command()
@click.option("--unused-days", default=90, type=int, help="Days of inactivity threshold")
@click.option("--json-output", "json_flag", is_flag=True, help="Output as JSON")
def audit(unused_days: int, json_flag: bool):
    """Audit vault for security issues."""
    vault = VaultManager()
    if not vault.exists():
        console.print("[red]No vault found. Run 'zenith-passkeys init' first.[/red]")
        raise SystemExit(1)

    password = click.prompt("Master password", hide_input=True)
    try:
        payload, _ = vault.unlock(password)
    except InvalidTag:
        console.print("[red]Wrong password.[/red]")
        raise SystemExit(1)

    issues = []
    now = datetime.now(timezone.utc)

    for c in payload.credentials:
        if c.last_used_at:
            last = datetime.fromisoformat(c.last_used_at)
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

    domains = set(c.rp_id for c in payload.credentials)
    for domain in domains:
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
            table.add_row(issue["severity"], issue["type"], issue["rp_id"], issue["detail"])
        console.print(table)
        raise SystemExit(1)
