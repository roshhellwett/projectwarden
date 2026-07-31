import pytest
from click.testing import CliRunner
from zenith_passkeys.main import cli

def test_version():
    runner = CliRunner()
    result = runner.invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert "1.0.0" in result.output

def test_help():
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    for cmd in ["init", "list", "export", "import", "backup", "audit", "lock", "config"]:
        assert cmd in result.output

def test_list_no_vault():
    runner = CliRunner()
    result = runner.invoke(cli, ["list"], input="test\n")
    assert result.exit_code == 1
    assert "No vault found" in result.output

def test_lock():
    runner = CliRunner()
    result = runner.invoke(cli, ["lock"])
    assert result.exit_code == 0
    assert "Vault locked" in result.output
