from click.testing import CliRunner

from zenith_passkeys.commands.backup_cmd import backup
from zenith_passkeys.core.crypto import VaultHeader
from zenith_passkeys.core.paths import get_vault_dir, get_vault_file, get_vault_lock, get_config_file
from zenith_passkeys.core.schema import Credential, VaultPayload
from zenith_passkeys.core.vault import VaultManager


def test_paths():
    d = get_vault_dir()
    assert str(d).endswith("zenith-passkeys")
    assert str(get_vault_file()).endswith("vault.enc")
    assert str(get_vault_lock()).endswith("vault.enc.lock")
    assert str(get_config_file()).endswith("config.toml")


def test_backup_create_and_restore(tmp_path, monkeypatch):
    vault_home = tmp_path / "home"
    monkeypatch.setenv("ZENITH_HOME", str(vault_home))

    vault = VaultManager()
    vault.create("TestPassword123!")

    # Add a sample credential to test retention
    def add_cred(p: VaultPayload):
        p.credentials.append(
            Credential(
                rp_id="github.com",
                credential_id="cred-12345",
                private_key="priv",
                public_key="pub",
                user_handle="user-handle",
                username="alice",
            )
        )
        return p

    _payload, mek = vault.unlock("TestPassword123!")
    vault.update(add_cred, mek)

    # 1. Create a backup in a custom location (e.g. simulating USB drive)
    backup_file = tmp_path / "usb_drive" / "my_backup.enc"
    runner = CliRunner()
    result = runner.invoke(backup, ["create", str(backup_file)], input="TestPassword123!\n")
    assert result.exit_code == 0
    assert backup_file.exists()
    assert "Vault backup successfully created!" in result.output

    # Verify backup is a valid encrypted vault
    blob = backup_file.read_bytes()
    header = VaultHeader.from_bytes(blob)
    assert header.version in (1, 2)

    # 2. Simulate restoring on a new machine / fresh folder
    restore_home = tmp_path / "new_machine_home"
    monkeypatch.setenv("ZENITH_HOME", str(restore_home))
    new_vault = VaultManager()
    assert not new_vault.exists()

    result = runner.invoke(backup, ["restore", str(backup_file)], input="TestPassword123!\n")
    assert result.exit_code == 0
    assert "Vault successfully restored!" in result.output
    assert new_vault.exists()

    # Unlock restored vault and verify credential was retained
    restored_p, _ = new_vault.unlock("TestPassword123!")
    assert len(restored_p.credentials) == 1
    assert restored_p.credentials[0].rp_id == "github.com"
    assert restored_p.credentials[0].username == "alice"


def test_backup_restore_wrong_password(tmp_path, monkeypatch):
    vault_home = tmp_path / "home"
    monkeypatch.setenv("ZENITH_HOME", str(vault_home))

    vault = VaultManager()
    vault.create("RealPassword123!")

    backup_file = tmp_path / "backup.enc"
    runner = CliRunner()
    result = runner.invoke(backup, ["create", str(backup_file)], input="RealPassword123!\n")
    assert result.exit_code == 0

    # Try to restore with wrong password
    result = runner.invoke(backup, ["restore", str(backup_file)], input="WrongPassword999!\n")
    assert result.exit_code != 0
    assert "That password does not unlock this backup vault" in result.output


def test_backup_restore_corrupted_file(tmp_path, monkeypatch):
    corrupted_file = tmp_path / "corrupt.enc"
    corrupted_file.write_bytes(b"invalid_header_garbage_data_here")

    runner = CliRunner()
    result = runner.invoke(backup, ["restore", str(corrupted_file)])
    assert result.exit_code != 0
    assert "corrupted or not a valid Zenith vault" in result.output


def test_no_cloud_dependencies_required():
    """Verify that backup operations require zero cloud or google modules."""
    import sys
    for mod in list(sys.modules.keys()):
        assert not mod.startswith("google.auth")
        assert not mod.startswith("googleapiclient")
