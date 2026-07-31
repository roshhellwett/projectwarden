import os
import tempfile
import pytest
from pathlib import Path
from zenith_passkeys.core.vault import VaultManager
from zenith_passkeys.core.schema import VaultPayload, Credential
from cryptography.exceptions import InvalidTag

@pytest.fixture
def tmp_vault():
    with tempfile.TemporaryDirectory() as td:
        vpath = Path(td) / "vault.enc"
        v = VaultManager(vault_path=vpath)
        yield v

def test_create_vault(tmp_vault):
    recovery, mek = tmp_vault.create("testpassword")
    assert tmp_vault.exists()
    assert len(recovery) > 0
    assert len(mek) == 32

def test_unlock_vault(tmp_vault):
    tmp_vault.create("testpassword")
    payload, mek = tmp_vault.unlock("testpassword")
    assert payload.version == 1
    assert len(payload.credentials) == 0

def test_unlock_wrong_password(tmp_vault):
    tmp_vault.create("testpassword")
    with pytest.raises(InvalidTag):
        tmp_vault.unlock("wrongpassword")

def test_save_and_reload(tmp_vault):
    _, mek = tmp_vault.create("testpassword")
    payload = VaultPayload()
    payload.credentials.append(Credential(
        rp_id="example.com",
        credential_id="test_id",
        private_key="key",
        public_key="pub",
        user_handle="handle",
        username="user",
        counter=0,
        algorithm=-7,
    ))
    tmp_vault.save(payload, mek)

    payload2, _ = tmp_vault.unlock("testpassword")
    assert len(payload2.credentials) == 1
    assert payload2.credentials[0].rp_id == "example.com"

def test_change_password(tmp_vault):
    tmp_vault.create("oldpassword")
    tmp_vault.change_password("oldpassword", "newpassword")
    with pytest.raises(InvalidTag):
        tmp_vault.unlock("oldpassword")
    payload, _ = tmp_vault.unlock("newpassword")
    assert payload is not None

def test_unlock_with_recovery(tmp_vault):
    recovery_display, mek = tmp_vault.create("testpassword")
    from zenith_passkeys.core.recovery import parse_recovery_key
    recovery_raw = parse_recovery_key(recovery_display)
    payload, recovered_mek = tmp_vault.unlock_with_recovery(recovery_raw)
    assert mek == recovered_mek
