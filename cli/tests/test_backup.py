import pytest
from zenith_passkeys.backup.base import BackupProvider
from zenith_passkeys.core.paths import get_vault_dir, get_vault_file, get_vault_lock, get_config_file

def test_paths():
    d = get_vault_dir()
    assert str(d).endswith("zenith-passkeys")
    assert str(get_vault_file()).endswith("vault.enc")
    assert str(get_vault_lock()).endswith("vault.enc.lock")
    assert str(get_config_file()).endswith("config.toml")

def test_backup_protocol_has_methods():
    required = ["upload", "download", "is_authenticated", "authenticate", "revoke"]
    for method in required:
        assert hasattr(BackupProvider, method), f"Missing method: {method}"
