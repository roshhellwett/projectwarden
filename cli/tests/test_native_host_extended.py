import json
from pathlib import Path
from zenith_passkeys.core.vault import VaultManager
from zenith_passkeys.native_host.host import NativeHost


def test_native_host_extended_lifecycle(tmp_path: Path):
    vault_file = tmp_path / "vault.enc"

    # Setup NativeHost with temporary isolated vault
    host = NativeHost()
    host.vault = VaultManager(vault_path=vault_file)

    # 1. Create vault
    create_resp = host._dispatch({"action": "create_vault", "password": "Password123!"})
    assert "recovery_key" in create_resp
    assert host.mek is not None
    assert host.payload is not None

    # 2. Add sample credential
    sample_cred = {
        "rp_id": "example.com",
        "credential_id": "cred-12345",
        "private_key": "pk-secret",
        "public_key": "pk-public",
        "user_handle": "uh-1",
        "username": "alice",
        "counter": 5,
        "algorithm": -7,
        "created_at": "2026-01-01T00:00:00+00:00",
        "last_used_at": "2026-01-01T00:00:00+00:00",
    }
    import_resp = host._dispatch({"action": "import_vault", "credentials": [sample_cred]})
    assert import_resp.get("success") is True
    assert import_resp.get("importedCount") == 1

    # 3. Test list credentials
    list_resp = host._dispatch({"action": "list_credentials"})
    assert len(list_resp.get("credentials", [])) == 1
    assert list_resp["credentials"][0]["username"] == "alice"

    # 4. Test audit report
    audit_resp = host._dispatch({"action": "get_audit_report", "unusedDays": 30})
    assert "healthScore" in audit_resp
    assert "issues" in audit_resp
    assert len(audit_resp["issues"]) >= 1  # Should find stale credential
    assert audit_resp["issues"][0]["type"] == "stale"

    # 5. Test action logs
    logs_resp = host._dispatch({"action": "get_action_logs"})
    assert "logs" in logs_resp
    assert len(logs_resp["logs"]) >= 1

    # 6. Test backup creation
    backup_resp = host._dispatch({"action": "get_backup_blob"})
    assert "backupBlob" in backup_resp
    assert "sha256" in backup_resp
    assert backup_resp["credentialCount"] == 1
    blob_b64 = backup_resp["backupBlob"]

    # 7. Test export vault (both plain and encrypted)
    export_plain = host._dispatch({"action": "export_vault"})
    assert export_plain.get("encrypted") is False
    parsed_plain = json.loads(export_plain["data"])
    assert len(parsed_plain["credentials"]) == 1

    export_enc = host._dispatch({"action": "export_vault", "password": "ExportPassword999!"})
    assert export_enc.get("encrypted") is True
    parsed_enc = json.loads(export_enc["data"])
    assert parsed_enc["format"] == "zenith-encrypted-export"

    # 8. Test change password
    change_resp = host._dispatch({
        "action": "change_password",
        "oldPassword": "Password123!",
        "newPassword": "NewPassword456!",
    })
    assert change_resp.get("success") is True

    # Lock and verify unlock with new password
    host._dispatch({"action": "lock"})
    assert host.mek is None

    unlock_resp = host._dispatch({"action": "unlock", "password": "NewPassword456!"})
    assert unlock_resp.get("success") is True
    assert host.mek is not None

    # 9. Test restore backup blob with original password
    restore_fail = host._dispatch({
        "action": "restore_backup_blob",
        "backupBlob": blob_b64,
        "password": "WrongPassword!",
    })
    assert "error" in restore_fail

    restore_ok = host._dispatch({
        "action": "restore_backup_blob",
        "backupBlob": blob_b64,
        "password": "Password123!",
    })
    assert restore_ok.get("success") is True
    assert restore_ok.get("credentialCount") == 1
