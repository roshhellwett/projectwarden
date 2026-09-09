import sys

import click
from rich.console import Console
from rich.panel import Panel

from .commands import (
    audit_cmd,
    backup_cmd,
    change_password_cmd,
    config_cmd,
    delete_cmd,
    export_cmd,
    import_cmd,
    init_cmd,
    list_cmd,
    lock_cmd,
    logs_cmd,
    recover_cmd,
    rotate_recovery_cmd,
)
from .core.errors import make_error_code

__version__ = "1.1.2"


class ErrorHandlingGroup(click.Group):
    def invoke(self, ctx):
        try:
            return super().invoke(ctx)
        except (click.ClickException, click.exceptions.Exit, SystemExit):
            raise
        except (click.Abort, KeyboardInterrupt):
            sys.exit(130)
        except Exception as e:  # noqa: BLE001 - last-resort handler shows support info
            error_code = make_error_code(e)
            console = Console()
            console.print()
            console.print(Panel(
                f"[bold red]Something went wrong in Zenith Passkeys.[/bold red]\n\n"
                f"Please copy the error code below and contact support:\n"
                f"[bold]zenithprojects@icloud.com[/bold]\n\n"
                f"[bold yellow]Error Code:[/bold yellow]\n"
                f"[dim]{error_code}[/dim]",
                title="Fatal Error",
                border_style="red"
            ))
            sys.exit(1)


@click.group(cls=ErrorHandlingGroup)
@click.version_option(
    version=__version__,
    prog_name="zenith-passkeys",
    message="%(prog)s %(version)s\nBuilt and managed by Zenith Open Source Projects",
)
def cli():
    """Zenith Passkeys - local-first, air-gapped passkey manager.

    Built and managed by Zenith Open Source Projects.
    """


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
cli.add_command(logs_cmd.logs)
cli.add_command(recover_cmd.recover)
cli.add_command(rotate_recovery_cmd.rotate_recovery)
