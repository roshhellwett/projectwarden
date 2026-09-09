from unittest.mock import patch
import pytest
from click.testing import CliRunner
from zenith_passkeys.main import cli

def test_version():
    runner = CliRunner()
    result = runner.invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert "1.1.2" in result.output
    assert "Zenith Open Source Projects" in result.output

def test_help():
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "Zenith Open Source Projects" in result.output
    for cmd in ["init", "list", "export", "import", "backup", "audit", "lock", "config"]:
        assert cmd in result.output

    backup_result = runner.invoke(cli, ["backup", "--help"])
    assert backup_result.exit_code == 0
    assert "create" in backup_result.output
    assert "restore" in backup_result.output

@patch("zenith_passkeys.core.vault.VaultManager.exists", return_value=False)
def test_list_no_vault(mock_exists):
    runner = CliRunner()
    result = runner.invoke(cli, ["list"], input="test\n")
    assert result.exit_code == 1
    assert "No vault found" in result.output

def test_lock():
    runner = CliRunner()
    result = runner.invoke(cli, ["lock"])
    assert result.exit_code == 0
    assert "Vault locked" in result.output or "Vault lock requested" in result.output
