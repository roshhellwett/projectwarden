import click
import traceback
import base64
import sys
from rich.console import Console
from rich.panel import Panel
from .commands import init_cmd, list_cmd, export_cmd, import_cmd, backup_cmd, audit_cmd, lock_cmd, config_cmd, change_password_cmd, delete_cmd

class ErrorHandlingGroup(click.Group):
    def invoke(self, ctx):
        try:
            return super().invoke(ctx)
        except click.ClickException:
            raise
        except click.exceptions.Exit:
            raise
        except Exception as e:
            error_code = base64.b64encode(str(e).encode("utf-8")).decode("utf-8")
            
            console = Console()
            console.print()
            console.print(Panel(
                f"[bold red]An unexpected error occurred in Zenith Passkeys.[/bold red]\n\n"
                f"We are sorry for the issue. Please copy the error code below\n"
                f"and provide it to support for assistance.\n\n"
                f"[bold yellow]Error Code:[/bold yellow]\n"
                f"[dim]{error_code}[/dim]",
                title="⚠️ Fatal Error",
                border_style="red"
            ))
            sys.exit(1)

@click.group(cls=ErrorHandlingGroup)
@click.version_option(version="1.0.0", prog_name="zenith-passkeys")
def cli():
    """Zenith Passkeys — local-first passkey manager."""
    pass

cli.add_command(init_cmd.init)
cli.add_command(list_cmd.list_credentials, name="list")
cli.add_command(export_cmd.export)
cli.add_command(import_cmd.import_vault, name="import")
cli.add_command(backup_cmd.backup)
cli.add_command(audit_cmd.audit)
cli.add_command(lock_cmd.lock)
cli.add_command(config_cmd.config)
cli.add_command(change_password_cmd.change_password)
cli.add_command(delete_cmd.delete)

