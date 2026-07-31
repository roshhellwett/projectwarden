from unittest.mock import patch
import pytest
from zenith_passkeys.native_host.protocol import MAX_MESSAGE_SIZE
from zenith_passkeys.native_host.host import NativeHost

def test_host_init():
    host = NativeHost()
    assert host.mek is None
    assert host.payload is None
    assert host.idle_timeout == 900

def test_host_ping():
    host = NativeHost()
    resp = host._ping({})
    assert resp["status"] == "ok"
    assert resp["version"] == "1.0.0"

@patch("zenith_passkeys.core.vault.VaultManager.exists", return_value=False)
def test_host_no_vault(mock_exists):
    host = NativeHost()
    resp = host._vault_exists({})
    assert resp["exists"] is False

def test_host_is_locked():
    host = NativeHost()
    resp = host._is_unlocked({})
    assert resp["unlocked"] is False

def test_host_lock():
    host = NativeHost()
    host.mek = b"\x00" * 32
    host._do_lock({})
    assert host.mek is None

def test_max_message_size():
    assert MAX_MESSAGE_SIZE == 1024 * 1024
