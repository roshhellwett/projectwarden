import click
from .commands import init_cmd, list_cmd, export_cmd, import_cmd, backup_cmd, audit_cmd, lock_cmd, config_cmd

@click.group()
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
