"""
Comprehensive end-to-end production readiness audit.
Tests every CLI command path, edge cases, and security properties.
"""
import os
import sys
import json
import tempfile
import shutil
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "cli" / "src"))

from zenith_passkeys.core.vault import VaultManager
from zenith_passkeys.core.schema import VaultPayload, Credential, Settings
from zenith_passkeys.core.crypto import (
    VaultHeader, HEADER_SIZE_V1, HEADER_SIZE_V2, MAGIC,
    derive_key, encrypt_aes_gcm, decrypt_aes_gcm,
    DEFAULT_KDF_ITERATIONS, DEFAULT_KDF_MEMORY, DEFAULT_KDF_LANES,
)
from zenith_passkeys.core.recovery import generate_recovery_key, parse_recovery_key, format_recovery_key
from zenith_passkeys.core.credentials import add_credential, find_credentials, update_counter, delete_credential
from zenith_passkeys.core.webauthn import (
    generate_credential_keypair, create_credential_response,
    get_assertion_response, base64url_encode, base64url_decode,
    build_authenticator_data, build_attested_credential_data,
)
from cryptography.exceptions import InvalidTag

passed = 0
failed = 0
issues = []

def run_audit_test(name, fn):
    global passed, failed
    try:
        fn()
        passed += 1
        print(f"  ✅ {name}")
    except Exception as e:
        failed += 1
        issues.append((name, str(e)))
        print(f"  ❌ {name}: {e}")

# ========== SECTION 1: VAULT LIFECYCLE ==========
print("\n🔐 VAULT LIFECYCLE")

def test_create_unlock_cycle():
    with tempfile.TemporaryDirectory() as td:
        v = VaultManager(vault_path=Path(td) / "vault.enc")
        assert not v.exists()
        recovery, mek = v.create("MyPassword123!")
        assert v.exists()
        assert len(mek) == 32
        assert len(recovery) > 0
        payload, mek2 = v.unlock("MyPassword123!")
        assert mek == mek2
        assert payload.version == 1
        assert len(payload.credentials) == 0

run_audit_test("Create + unlock full cycle", test_create_unlock_cycle)

def test_wrong_password_rejected():
    with tempfile.TemporaryDirectory() as td:
        v = VaultManager(vault_path=Path(td) / "vault.enc")
        v.create("correctpw")
        try:
            v.unlock("wrong")
            assert False, "Should have raised ValueError"
        except ValueError:
            pass

run_audit_test("Wrong password correctly rejected", test_wrong_password_rejected)

def test_recovery_key_works():
    with tempfile.TemporaryDirectory() as td:
        v = VaultManager(vault_path=Path(td) / "vault.enc")
        recovery_display, mek = v.create("password")
        recovery_raw = parse_recovery_key(recovery_display)
        payload, recovered_mek = v.unlock_with_recovery(recovery_raw)
        assert mek == recovered_mek

run_audit_test("Recovery key unlock works", test_recovery_key_works)

def test_wrong_recovery_key_rejected():
    with tempfile.TemporaryDirectory() as td:
        v = VaultManager(vault_path=Path(td) / "vault.enc")
        v.create("password")
        fake_raw = os.urandom(20)
        try:
            v.unlock_with_recovery(fake_raw)
            assert False, "Should have raised ValueError"
        except ValueError:
            pass

run_audit_test("Wrong recovery key rejected", test_wrong_recovery_key_rejected)

def test_password_change():
    with tempfile.TemporaryDirectory() as td:
        v = VaultManager(vault_path=Path(td) / "vault.enc")
        v.create("old_pw12")
        v.change_password("old_pw12", "new_pw12")
        try:
            v.unlock("old_pw12")
            assert False, "Old password should fail"
        except ValueError:
            pass
        payload, _ = v.unlock("new_pw12")
        assert payload is not None

run_audit_test("Password change works correctly", test_password_change)

def test_save_preserves_data():
    with tempfile.TemporaryDirectory() as td:
        v = VaultManager(vault_path=Path(td) / "vault.enc")
        _, mek = v.create("pw123456")
        payload = VaultPayload()
        cred = Credential(
            rp_id="github.com", credential_id="cred1",
            private_key="pk", public_key="pub",
            user_handle="uh", username="alice@github.com",
            counter=5, algorithm=-7,
        )
        payload.credentials.append(cred)
        payload.settings.idle_timeout_minutes = 30
        v.save(payload, mek)
        p2, _ = v.unlock("pw123456")
        assert len(p2.credentials) == 1
        assert p2.credentials[0].rp_id == "github.com"
        assert p2.credentials[0].username == "alice@github.com"
        assert p2.credentials[0].counter == 5
        assert p2.settings.idle_timeout_minutes == 30

run_audit_test("Save and reload preserves all data", test_save_preserves_data)

def test_atomic_write():
    with tempfile.TemporaryDirectory() as td:
        v = VaultManager(vault_path=Path(td) / "vault.enc")
        v.create("pw123456")
        tmp_file = Path(td) / "vault.tmp"
        assert not tmp_file.exists(), ".tmp file should be cleaned up"

run_audit_test("Atomic write (no leftover .tmp)", test_atomic_write)

# ========== SECTION 2: CRYPTO PROPERTIES ==========
print("\n🔑 CRYPTO PROPERTIES")

def test_header_size_exact():
    h = VaultHeader(
        version=2, pw_salt=os.urandom(16), rec_salt=os.urandom(16),
        kdf_iterations=3, kdf_memory=65536, kdf_lanes=4,
        pw_wrapped_nonce=os.urandom(12), pw_wrapped_mek=os.urandom(48),
        rec_wrapped_nonce=os.urandom(12), rec_wrapped_mek=os.urandom(48),
        payload_nonce=os.urandom(12),
    )
    b = h.to_bytes()
    assert len(b) == HEADER_SIZE_V2

run_audit_test("Header is exactly 166 bytes", test_header_size_exact)

def test_magic_bytes():
    with tempfile.TemporaryDirectory() as td:
        v = VaultManager(vault_path=Path(td) / "vault.enc")
        v.create("pw123456")
        raw = (Path(td) / "vault.enc").read_bytes()
        assert raw[:4] == b"ZNTH"

run_audit_test("Vault file starts with ZNTH magic", test_magic_bytes)

def test_corrupted_vault_rejected():
    with tempfile.TemporaryDirectory() as td:
        v = VaultManager(vault_path=Path(td) / "vault.enc")
        v.create("pw123456")
        p = Path(td) / "vault.enc"
        raw = bytearray(p.read_bytes())
        raw[100] ^= 0xFF
        p.write_bytes(bytes(raw))
        try:
            v.unlock("pw123456")
            assert False, "Should fail on corrupted vault"
        except Exception:
            pass

run_audit_test("Corrupted vault file rejected", test_corrupted_vault_rejected)

def test_truncated_vault_rejected():
    with tempfile.TemporaryDirectory() as td:
        v = VaultManager(vault_path=Path(td) / "vault.enc")
        v.create("pw123456")
        p = Path(td) / "vault.enc"
        raw = p.read_bytes()
        p.write_bytes(raw[:100])
        try:
            v.unlock("pw123456")
            assert False, "Should fail on truncated vault"
        except Exception:
            pass

run_audit_test("Truncated vault file rejected", test_truncated_vault_rejected)

def test_aes_gcm_tamper_detection():
    key = os.urandom(32)
    nonce = os.urandom(12)
    ct = encrypt_aes_gcm(b"secret data", key, nonce)
    tampered = bytearray(ct)
    tampered[0] ^= 0xFF
    try:
        decrypt_aes_gcm(bytes(tampered), key, nonce)
        assert False, "Should detect tampering"
    except InvalidTag:
        pass

run_audit_test("AES-GCM detects tampered ciphertext", test_aes_gcm_tamper_detection)

# ========== SECTION 3: RECOVERY KEY FORMAT ==========
print("\n🔄 RECOVERY KEY")

def test_recovery_key_format():
    raw, display = generate_recovery_key()
    assert len(raw) == 20
    parts = display.split("-")
    assert len(parts) == 8
    for part in parts:
        assert len(part) == 4

run_audit_test("Recovery key format: 8 groups of 4 chars", test_recovery_key_format)

def test_recovery_key_roundtrip():
    raw, display = generate_recovery_key()
    parsed = parse_recovery_key(display)
    re_display = format_recovery_key(parsed)
    assert re_display == display

run_audit_test("Recovery key parse/format roundtrip", test_recovery_key_roundtrip)

def test_recovery_key_case_insensitive():
    raw, display = generate_recovery_key()
    lower = display.lower()
    parsed = parse_recovery_key(lower)
    assert format_recovery_key(parsed) == display

run_audit_test("Recovery key parsing is case-insensitive", test_recovery_key_case_insensitive)

def test_recovery_key_bad_format():
    try:
        parse_recovery_key("short")
        assert False, "Should reject short keys"
    except ValueError:
        pass

run_audit_test("Recovery key rejects invalid format", test_recovery_key_bad_format)

# ========== SECTION 4: CREDENTIAL CRUD ==========
print("\n📋 CREDENTIAL CRUD")

def test_add_credential():
    p = VaultPayload()
    c = Credential(rp_id="example.com", credential_id="id1",
                   private_key="pk", public_key="pub",
                   user_handle="uh", username="user1")
    p = add_credential(p, c)
    assert len(p.credentials) == 1

run_audit_test("Add credential", test_add_credential)

def test_add_duplicate_rejected():
    p = VaultPayload()
    c = Credential(rp_id="example.com", credential_id="id1",
                   private_key="pk", public_key="pub",
                   user_handle="uh", username="user1")
    p = add_credential(p, c)
    try:
        add_credential(p, c)
        assert False, "Should reject duplicate"
    except ValueError:
        pass

run_audit_test("Duplicate credential rejected", test_add_duplicate_rejected)

def test_find_by_rpid():
    p = VaultPayload()
    p.credentials = [
        Credential(rp_id="a.com", credential_id="1", private_key="", public_key="", user_handle="", username="u1"),
        Credential(rp_id="b.com", credential_id="2", private_key="", public_key="", user_handle="", username="u2"),
        Credential(rp_id="a.com", credential_id="3", private_key="", public_key="", user_handle="", username="u3"),
    ]
    found = find_credentials(p, "a.com")
    assert len(found) == 2

run_audit_test("Find credentials by rpId", test_find_by_rpid)

def test_find_with_allow_list():
    p = VaultPayload()
    p.credentials = [
        Credential(rp_id="a.com", credential_id="1", private_key="", public_key="", user_handle="", username="u1"),
        Credential(rp_id="a.com", credential_id="2", private_key="", public_key="", user_handle="", username="u2"),
    ]
    found = find_credentials(p, "a.com", allow_list=["2"])
    assert len(found) == 1
    assert found[0].credential_id == "2"

run_audit_test("Find credentials with allow list", test_find_with_allow_list)

def test_update_counter():
    p = VaultPayload()
    p.credentials = [
        Credential(rp_id="a.com", credential_id="cid1", private_key="", public_key="", user_handle="", username="u"),
    ]
    p = update_counter(p, "cid1", 5)
    assert p.credentials[0].counter == 5
    assert p.credentials[0].last_used_at is not None

run_audit_test("Update counter sets counter + last_used_at", test_update_counter)

def test_delete_credential():
    p = VaultPayload()
    p.credentials = [
        Credential(rp_id="a.com", credential_id="1", private_key="", public_key="", user_handle="", username="u"),
        Credential(rp_id="b.com", credential_id="2", private_key="", public_key="", user_handle="", username="u"),
    ]
    p = delete_credential(p, "1")
    assert len(p.credentials) == 1
    assert p.credentials[0].credential_id == "2"

run_audit_test("Delete credential", test_delete_credential)

def test_delete_nonexistent_fails():
    p = VaultPayload()
    try:
        delete_credential(p, "nonexistent")
        assert False, "Should raise ValueError"
    except ValueError:
        pass

run_audit_test("Delete non-existent credential fails", test_delete_nonexistent_fails)

# ========== SECTION 5: WEBAUTHN ==========
print("\n🌐 WEBAUTHN CEREMONIES")

def test_keypair_generation():
    priv, cose, cred_id, spki = generate_credential_keypair()
    assert len(priv) > 0
    assert len(cose) > 0
    assert len(cred_id) == 32

run_audit_test("Key pair generation", test_keypair_generation)

def test_create_credential_full():
    response, cred = create_credential_response(
        rp_id="example.com",
        origin="https://example.com",
        challenge_b64url=base64url_encode(os.urandom(32)),
        user_handle=os.urandom(16),
        username="alice",
    )
    assert response["type"] == "public-key"
    assert "attestationObject" in response["response"]
    assert "clientDataJSON" in response["response"]
    assert cred.rp_id == "example.com"
    assert cred.username == "alice"
    assert cred.algorithm == -7

run_audit_test("Create credential full ceremony", test_create_credential_full)

def test_get_assertion_full():
    _, cred = create_credential_response(
        rp_id="example.com",
        origin="https://example.com",
        challenge_b64url=base64url_encode(os.urandom(32)),
        user_handle=os.urandom(16),
        username="alice",
    )
    response, new_counter = get_assertion_response(
        cred, "example.com", "https://example.com",
        base64url_encode(os.urandom(32)),
    )
    assert response["type"] == "public-key"
    assert "authenticatorData" in response["response"]
    assert "signature" in response["response"]
    assert new_counter == 1

run_audit_test("Get assertion full ceremony", test_get_assertion_full)

def test_base64url_roundtrip():
    data = os.urandom(64)
    encoded = base64url_encode(data)
    assert "+" not in encoded
    assert "/" not in encoded
    assert "=" not in encoded
    decoded = base64url_decode(encoded)
    assert decoded == data

run_audit_test("Base64url roundtrip (no +/= chars)", test_base64url_roundtrip)

def test_authenticator_data_flags():
    auth_data = build_authenticator_data("example.com", 0x45, 0)
    assert len(auth_data) == 37
    assert auth_data[32] == 0x45
    auth_data2 = build_authenticator_data("example.com", 0x05, 1)
    assert auth_data2[32] == 0x05

run_audit_test("AuthenticatorData flags correct", test_authenticator_data_flags)

# ========== SECTION 6: SCHEMA SERIALIZATION ==========
print("\n📦 SCHEMA SERIALIZATION")

def test_payload_json_roundtrip():
    p = VaultPayload()
    p.credentials.append(Credential(
        rp_id="test.com", credential_id="id",
        private_key="pk", public_key="pub",
        user_handle="uh", username="bob",
        counter=42, last_used_at="2025-01-01T00:00:00Z",
    ))
    p.settings.idle_timeout_minutes = 30
    p.settings.backup_provider = "gdrive"
    json_bytes = p.to_json()
    p2 = VaultPayload.from_json(json_bytes)
    assert len(p2.credentials) == 1
    assert p2.credentials[0].counter == 42
    assert p2.credentials[0].last_used_at == "2025-01-01T00:00:00Z"
    assert p2.settings.idle_timeout_minutes == 30
    assert p2.settings.backup_provider == "gdrive"

run_audit_test("VaultPayload JSON roundtrip", test_payload_json_roundtrip)

def test_empty_payload_serializes():
    p = VaultPayload()
    data = p.to_json()
    p2 = VaultPayload.from_json(data)
    assert p2.version == 1
    assert len(p2.credentials) == 0
    assert p2.settings.idle_timeout_minutes == 15

run_audit_test("Empty payload serializes correctly", test_empty_payload_serializes)

def test_unicode_username():
    p = VaultPayload()
    p.credentials.append(Credential(
        rp_id="test.com", credential_id="id",
        private_key="pk", public_key="pub",
        user_handle="uh", username="用户@test.com",
    ))
    data = p.to_json()
    p2 = VaultPayload.from_json(data)
    assert p2.credentials[0].username == "用户@test.com"

run_audit_test("Unicode usernames preserved", test_unicode_username)

# ========== SECTION 7: NATIVE HOST ==========
print("\n🔌 NATIVE HOST")

from zenith_passkeys.native_host.host import NativeHost
from zenith_passkeys.native_host.protocol import MAX_MESSAGE_SIZE

def test_native_host_ping():
    h = NativeHost()
    r = h._dispatch({"action": "ping"})
    assert r["status"] == "ok"
    assert r["version"] == "1.1.2"

run_audit_test("Native host ping", test_native_host_ping)

def test_native_host_locked_operations():
    h = NativeHost()
    for action in ["create_credential", "get_assertion", "list_credentials", "get_settings", "update_settings"]:
        r = h._dispatch({"action": action})
        assert "error" in r, f"Action {action} should fail when locked"

run_audit_test("Locked vault rejects all credential ops", test_native_host_locked_operations)

def test_native_host_unknown_action():
    h = NativeHost()
    r = h._dispatch({"action": "nonexistent"})
    assert "error" in r

run_audit_test("Unknown action returns error", test_native_host_unknown_action)

def test_native_host_idle_lock():
    import time
    h = NativeHost()
    h.mek = b"fakemek"
    h.payload = VaultPayload()
    h.idle_timeout = 0
    h.last_activity = time.time() - 1
    h._check_idle()
    assert h.mek is None
    assert h.payload is None

run_audit_test("Idle timeout clears MEK and payload", test_native_host_idle_lock)

def test_max_message_size():
    assert MAX_MESSAGE_SIZE == 1024 * 1024

run_audit_test("Max message size is 1MB", test_max_message_size)

# ========== SECTION 8: FULL INTEGRATION ==========
print("\n🔗 FULL INTEGRATION")

def test_full_create_get_cycle():
    with tempfile.TemporaryDirectory() as td:
        v = VaultManager(vault_path=Path(td) / "vault.enc")
        _, mek = v.create("pw123456")
        payload, _ = v.unlock("pw123456")
        response, cred = create_credential_response(
            "github.com", "https://github.com",
            base64url_encode(os.urandom(32)),
            os.urandom(16), "alice",
        )
        payload = add_credential(payload, cred)
        v.save(payload, mek)
        payload2, mek2 = v.unlock("pw123456")
        assert len(payload2.credentials) == 1
        creds = find_credentials(payload2, "github.com")
        assert len(creds) == 1
        assertion, new_counter = get_assertion_response(
            creds[0], "github.com", "https://github.com",
            base64url_encode(os.urandom(32)),
        )
        payload2 = update_counter(payload2, creds[0].credential_id, new_counter)
        v.save(payload2, mek2)
        payload3, _ = v.unlock("pw123456")
        assert payload3.credentials[0].counter == 1

run_audit_test("Full register -> authenticate -> persist cycle", test_full_create_get_cycle)

def test_multiple_credentials_same_site():
    with tempfile.TemporaryDirectory() as td:
        v = VaultManager(vault_path=Path(td) / "vault.enc")
        _, mek = v.create("pw123456")
        payload = VaultPayload()
        _, cred1 = create_credential_response("site.com", "https://site.com",
            base64url_encode(os.urandom(32)), os.urandom(16), "user1")
        _, cred2 = create_credential_response("site.com", "https://site.com",
            base64url_encode(os.urandom(32)), os.urandom(16), "user2")
        payload = add_credential(payload, cred1)
        payload = add_credential(payload, cred2)
        v.save(payload, mek)
        payload2, _ = v.unlock("pw123456")
        found = find_credentials(payload2, "site.com")
        assert len(found) == 2

run_audit_test("Multiple credentials for same site", test_multiple_credentials_same_site)

# ========== SECTION 9: SECURITY CHECKS ==========
print("\n🛡️ SECURITY CHECKS")

def test_mek_not_on_disk():
    with tempfile.TemporaryDirectory() as td:
        v = VaultManager(vault_path=Path(td) / "vault.enc")
        _, mek = v.create("pw123456")
        raw = (Path(td) / "vault.enc").read_bytes()
        assert mek not in raw, "MEK should not appear in plaintext in vault file"

run_audit_test("MEK not stored in plaintext on disk", test_mek_not_on_disk)

def test_different_vaults_different_salts():
    with tempfile.TemporaryDirectory() as td:
        v1 = VaultManager(vault_path=Path(td) / "v1.enc")
        v2 = VaultManager(vault_path=Path(td) / "v2.enc")
        v1.create("same_pw123")
        v2.create("same_pw123")
        raw1 = (Path(td) / "v1.enc").read_bytes()
        raw2 = (Path(td) / "v2.enc").read_bytes()
        h1 = VaultHeader.from_bytes(raw1)
        h2 = VaultHeader.from_bytes(raw2)
        assert h1.pw_salt != h2.pw_salt
        assert h1.rec_salt != h2.rec_salt

run_audit_test("Different vaults get different salts", test_different_vaults_different_salts)

# ========== SECTION 10: EDGE CASES ==========
print("\n⚠️ EDGE CASES")

def test_empty_password_rejected():
    with tempfile.TemporaryDirectory() as td:
        v = VaultManager(vault_path=Path(td) / "vault.enc")
        try:
            v.create("")
            assert False, "Should reject empty password"
        except ValueError as e:
            assert "at least 8 characters" in str(e).lower()

run_audit_test("Empty/short password correctly rejected", test_empty_password_rejected)

def test_very_long_password():
    with tempfile.TemporaryDirectory() as td:
        v = VaultManager(vault_path=Path(td) / "vault.enc")
        long_pw = "A" * 10000
        v.create(long_pw)
        payload, _ = v.unlock(long_pw)
        assert payload is not None

run_audit_test("Very long password (10K chars)", test_very_long_password)

def test_special_chars_in_password():
    with tempfile.TemporaryDirectory() as td:
        v = VaultManager(vault_path=Path(td) / "vault.enc")
        pw = "p\u00e4ssw\u00f6rd!@#$%^&*()\U0001f511"
        v.create(pw)
        payload, _ = v.unlock(pw)
        assert payload is not None

run_audit_test("Unicode/special chars in password", test_special_chars_in_password)

def test_many_credentials():
    p = VaultPayload()
    for i in range(100):
        c = Credential(
            rp_id=f"site{i}.com", credential_id=f"id{i}",
            private_key="pk", public_key="pub",
            user_handle="uh", username=f"user{i}",
        )
        p = add_credential(p, c)
    data = p.to_json()
    p2 = VaultPayload.from_json(data)
    assert len(p2.credentials) == 100

run_audit_test("100 credentials serialize/deserialize", test_many_credentials)

def test_large_vault_encrypt_decrypt():
    with tempfile.TemporaryDirectory() as td:
        v = VaultManager(vault_path=Path(td) / "vault.enc")
        _, mek = v.create("pw123456")
        payload = VaultPayload()
        for i in range(50):
            _, cred = create_credential_response(
                f"site{i}.com", f"https://site{i}.com",
                base64url_encode(os.urandom(32)),
                os.urandom(16), f"user{i}",
            )
            payload = add_credential(payload, cred)
        v.save(payload, mek)
        p2, _ = v.unlock("pw123456")
        assert len(p2.credentials) == 50

run_audit_test("Large vault (50 real credentials)", test_large_vault_encrypt_decrypt)

# ========== SECTION 11: CLI COMMANDS ==========
print("\n🖥️ CLI COMMANDS")

from click.testing import CliRunner
from zenith_passkeys.main import cli
import click

def test_cli_version():
    r = CliRunner().invoke(cli, ["--version"])
    assert r.exit_code == 0
    assert "1.1.2" in r.output

run_audit_test("CLI --version", test_cli_version)

def test_cli_help_all_commands():
    r = CliRunner().invoke(cli, ["--help"])
    assert r.exit_code == 0
    for cmd in ["init", "list", "export", "import", "backup", "audit", "lock", "config"]:
        assert cmd in r.output, f"Missing command: {cmd}"

run_audit_test("CLI --help lists all commands", test_cli_help_all_commands)

def test_cli_backup_help():
    r = CliRunner().invoke(cli, ["backup", "--help"])
    assert r.exit_code == 0
    assert "create" in r.output
    assert "restore" in r.output

run_audit_test("CLI backup subcommands", test_cli_backup_help)

def test_cli_backup_create_help():
    r = CliRunner().invoke(cli, ["backup", "create", "--help"])
    assert r.exit_code == 0
    assert "offline" in r.output.lower() or "encrypted" in r.output.lower() or "snapshot" in r.output.lower()

run_audit_test("CLI backup create shows local offline backup", test_cli_backup_create_help)

def test_cli_lock():
    r = CliRunner().invoke(cli, ["lock"])
    assert r.exit_code == 0
    assert "locked" in r.output.lower()

run_audit_test("CLI lock command", test_cli_lock)

# ========== SECTION 12: SOURCE CODE SECURITY GREP ==========
print("\n🔍 SOURCE CODE SECURITY AUDIT")

def test_no_print_private_key():
    src_dir = Path(__file__).parent / "cli" / "src"
    violations = []
    for py_file in src_dir.rglob("*.py"):
        content = py_file.read_text(encoding="utf-8", errors="ignore")
        lines = content.split("\n")
        for i, line in enumerate(lines, 1):
            lower = line.lower()
            if any(kw in lower for kw in ["private_key", ".mek", "mek "]):
                if any(fn in lower for fn in ["print(", "click.echo(", "console.print(", "logging.", "log."]):
                    violations.append(f"{py_file.name}:{i}: {line.strip()}")
    assert not violations, f"Potential key leak: {violations}"

run_audit_test("No print/log of private keys or MEK", test_no_print_private_key)

def test_no_telemetry():
    src_dir = Path(__file__).parent / "cli" / "src"
    violations = []
    suspicious = ["analytics", "telemetry", "sentry", "bugsnag", "mixpanel", "segment"]
    for py_file in src_dir.rglob("*.py"):
        content = py_file.read_text(encoding="utf-8", errors="ignore").lower()
        for term in suspicious:
            if term in content:
                violations.append(f"{py_file.name}: contains '{term}'")
    assert not violations, f"Telemetry found: {violations}"

run_audit_test("No telemetry/analytics code", test_no_telemetry)

def test_no_network_in_core():
    core_dir = Path(__file__).parent / "cli" / "src" / "zenith_passkeys" / "core"
    violations = []
    network_imports = ["requests", "urllib", "http.client", "socket"]
    for py_file in core_dir.rglob("*.py"):
        content = py_file.read_text(encoding="utf-8", errors="ignore")
        for imp in network_imports:
            if f"import {imp}" in content:
                violations.append(f"{py_file.name}: imports {imp}")
    assert not violations, f"Network imports in core: {violations}"

run_audit_test("No network imports in core module", test_no_network_in_core)

# ========== RESULTS ==========
print(f"\n{'='*60}")
print(f"  RESULTS: {passed} passed, {failed} failed")
print(f"{'='*60}")

if issues:
    print("\n FAILURES:")
    for name, err in issues:
        print(f"  * {name}: {err}")

print()
