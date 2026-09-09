import tempfile
import pytest
from pathlib import Path
from zenith_passkeys.core.vault import VaultManager
from zenith_passkeys.core.schema import VaultPayload, Credential
from zenith_passkeys.core.recovery import parse_recovery_key

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
    assert isinstance(mek, bytearray)  # zeroizable

def test_unlock_vault(tmp_vault):
    tmp_vault.create("testpassword")
    payload, mek = tmp_vault.unlock("testpassword")
    assert payload.version == 1
    assert len(payload.credentials) == 0

def test_unlock_wrong_password(tmp_vault):
    tmp_vault.create("testpassword")
    with pytest.raises(ValueError, match="password"):
        tmp_vault.unlock("wrongpassword")

def test_unlock_with_recovery_wrong_key(tmp_vault):
    recovery, _ = tmp_vault.create("testpassword")
    tmp_vault.lock_path = None  # unused; keep symmetry
    with pytest.raises(ValueError, match="recovery"):
        tmp_vault.unlock_with_recovery(b"\x01" * 20)

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
    with pytest.raises(ValueError, match="password"):
        tmp_vault.unlock("oldpassword")
    payload, _ = tmp_vault.unlock("newpassword")
    assert payload is not None

def test_recovery_survives_password_change(tmp_vault):
    """F-001 regression: recovery key must keep working after change-password."""
    recovery_display, _ = tmp_vault.create("oldpassword")
    tmp_vault.change_password("oldpassword", "newpassword")
    payload, mek = tmp_vault.unlock_with_recovery(parse_recovery_key(recovery_display))
    assert payload is not None
    assert len(mek) == 32

def test_unlock_with_recovery(tmp_vault):
    recovery_display, mek = tmp_vault.create("testpassword")
    recovery_raw = parse_recovery_key(recovery_display)
    payload, recovered_mek = tmp_vault.unlock_with_recovery(recovery_raw)
    assert bytes(mek) == bytes(recovered_mek)

def test_set_password_with_recovery_keeps_recovery_usable(tmp_vault):
    """F-001 regression: recovery flow must not consume the recovery key."""
    recovery_display, _ = tmp_vault.create("originalpass1")
    raw = parse_recovery_key(recovery_display)
    mek = tmp_vault.set_password_with_recovery(raw, "brandnewpass9")
    # new password works
    payload, _ = tmp_vault.unlock("brandnewpass9")
    assert payload is not None
    # SAME recovery key still works after the recover flow
    payload2, mek2 = tmp_vault.unlock_with_recovery(parse_recovery_key(recovery_display))
    assert payload2 is not None
    assert bytes(mek) == bytes(mek2)

def test_change_password_rejects_short(tmp_vault):
    tmp_vault.create("oldpassword")
    with pytest.raises(ValueError, match="8 characters"):
        tmp_vault.change_password("oldpassword", "short")

def test_change_password_wrong_old(tmp_vault):
    tmp_vault.create("oldpassword")
    with pytest.raises(ValueError, match="password"):
        tmp_vault.change_password("wrongoldpass", "newpassword")
