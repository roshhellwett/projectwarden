import re
from click.testing import CliRunner
from zenith_passkeys.main import cli
from zenith_passkeys.core.vault import VaultManager

def test_cli_version_and_help():
    runner = CliRunner()
    res = runner.invoke(cli, ["--version"])
    assert res.exit_code == 0
    assert "1.1.2" in res.output

    res_help = runner.invoke(cli, ["--help"])
    assert res_help.exit_code == 0
    assert "recover" in res_help.output
    assert "init" in res_help.output
    assert "list" in res_help.output
    assert "export" in res_help.output
    assert "import" in res_help.output

def test_cli_recover_standalone_flow(tmp_path, monkeypatch):
    vault_file = tmp_path / "vault.enc"
    monkeypatch.setenv("ZENITH_HOME", str(tmp_path))

    runner = CliRunner()
    
    # 1. Recover without vault should fail
    res_no_vault = runner.invoke(cli, ["recover", "--key", "XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX"])
    assert res_no_vault.exit_code != 0

    # 2. Init vault
    vault = VaultManager(vault_path=vault_file)
    rec_key, mek = vault.create("OriginalPassword123!")

    # 3. Recover with invalid key format should fail
    res_bad_key = runner.invoke(cli, ["recover", "--key", "invalid-key"], input="NewPassword456!\nNewPassword456!\n")
    assert res_bad_key.exit_code != 0
    assert "Invalid recovery key" in res_bad_key.output

    # 4. Recover with valid key should succeed and reset password
    res_ok = runner.invoke(cli, ["recover", "--key", rec_key], input="NewPassword456!\nNewPassword456!\n")
    assert res_ok.exit_code == 0
    assert "Vault recovered successfully" in res_ok.output

    # 5. Verify old password fails and new password succeeds
    try:
        vault.unlock("OriginalPassword123!")
        assert False, "Old password should not unlock vault"
    except ValueError:
        pass

    payload, new_mek = vault.unlock("NewPassword456!")
    assert payload is not None
    assert new_mek is not None


def test_cli_rotate_recovery_key_flow(tmp_path, monkeypatch):
    vault_file = tmp_path / "vault.enc"
    monkeypatch.setenv("ZENITH_HOME", str(tmp_path))

    runner = CliRunner()
    vault = VaultManager(vault_path=vault_file)
    old_rec_key, _ = vault.create("MasterPass123!")

    # Rotate recovery key via CLI
    res = runner.invoke(cli, ["rotate-recovery-key", "--password", "MasterPass123!"])
    assert res.exit_code == 0
    assert "Emergency Recovery Key rotated successfully" in res.output

    match = re.search(r"([A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4})", res.output)
    assert match is not None
    new_rec_key = match.group(1)
    assert new_rec_key != old_rec_key

    # Old recovery key should fail
    res_old = runner.invoke(cli, ["recover", "--key", old_rec_key], input="NewPass789!\nNewPass789!\n")
    assert res_old.exit_code != 0
    assert "Recovery failed" in res_old.output

    # New recovery key should succeed
    res_new = runner.invoke(cli, ["recover", "--key", new_rec_key], input="NewPass789!\nNewPass789!\n")
    assert res_new.exit_code == 0
    assert "Vault recovered successfully" in res_new.output


def test_cli_abort_handling_no_fatal_error(tmp_path, monkeypatch):
    # Tests that cancelling a prompt does not print the 'py3.14||' fatal error box
    monkeypatch.setenv("ZENITH_HOME", str(tmp_path))
    runner = CliRunner()
    res = runner.invoke(cli, ["recover"], input="\n")
    assert "py3." not in res.output
