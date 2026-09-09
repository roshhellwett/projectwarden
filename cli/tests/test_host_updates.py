import json
import pytest
from pathlib import Path
from zenith_passkeys.native_host.host import NativeHost
from zenith_passkeys.core.vault import VaultManager

def test_host_selected_credential_id_assertion(tmp_path):
    vault_file = tmp_path / "vault.enc"
    host = NativeHost()
    host.vault = VaultManager(vault_path=vault_file)
    
    # Create vault
    create_resp = host._create_vault({"password": "TestMasterPassword123!"})
    assert "recovery_key" in create_resp
    
    # Register 2 credentials for the same rp_id
    cred1_req = {
        "options": {
            "rp": {"id": "example.com", "name": "Example"},
            "user": {"name": "alice@example.com", "displayName": "Alice"},
            "challenge": "dGVzdGNoYWxsZW5nZQ"
        },
        "origin": "https://example.com"
    }
    r1 = host._create_credential(cred1_req)
    assert "credential" in r1
    id1 = r1["credential"]["id"]

    cred2_req = {
        "options": {
            "rp": {"id": "example.com", "name": "Example"},
            "user": {"name": "bob@example.com", "displayName": "Bob"},
            "challenge": "dGVzdGNoYWxsZW5nZQ"
        },
        "origin": "https://example.com"
    }
    r2 = host._create_credential(cred2_req)
    assert "credential" in r2
    id2 = r2["credential"]["id"]

    # Verify list shows both
    creds_list = host._list_credentials({})["credentials"]
    assert len(creds_list) == 2

    # Assertion without selectedCredentialId defaults to candidates[-1] (id2)
    assert_default = host._get_assertion({
        "options": {
            "rpId": "example.com",
            "challenge": "dGVzdGNoYWxsZW5nZQ"
        },
        "origin": "https://example.com"
    })
    assert assert_default["credential"]["id"] == id2

    # Assertion WITH selectedCredentialId for Alice (id1) must sign with Alice's key!
    assert_alice = host._get_assertion({
        "options": {
            "rpId": "example.com",
            "challenge": "dGVzdGNoYWxsZW5nZQ",
            "selectedCredentialId": id1
        },
        "origin": "https://example.com"
    })
    assert assert_alice["credential"]["id"] == id1

def test_host_encrypted_export_import(tmp_path):
    vault_file = tmp_path / "vault.enc"
    host = NativeHost()
    host.vault = VaultManager(vault_path=vault_file)
    host._create_vault({"password": "TestMasterPassword123!"})
    
    # Create a credential
    host._create_credential({
        "options": {
            "rp": {"id": "service.com", "name": "Service"},
            "user": {"name": "charlie@service.com", "displayName": "Charlie"},
            "challenge": "dGVzdGNoYWxsZW5nZQ"
        },
        "origin": "https://service.com"
    })

    # Export with password
    export_resp = host._export_vault({"password": "ExportSecretPass999!"})
    assert export_resp["encrypted"] is True
    container = json.loads(export_resp["data"])
    assert container["format"] == "zenith-encrypted-export"
    assert container["kdf"] == "argon2id"

    # Create a second fresh vault and import the encrypted export
    vault_file2 = tmp_path / "vault2.enc"
    host2 = NativeHost()
    host2.vault = VaultManager(vault_path=vault_file2)
    host2._create_vault({"password": "AnotherMasterPassword456!"})

    # Wrong password fails
    fail_import = host2._import_vault({
        "encrypted_export": container,
        "password": "WrongPassword!"
    })
    assert "error" in fail_import

    # Correct password succeeds
    success_import = host2._import_vault({
        "encrypted_export": container,
        "password": "ExportSecretPass999!"
    })
    assert success_import.get("success") is True
    assert success_import.get("importedCount") == 1

    # Verify imported credential is functional in vault 2
    creds2 = host2._list_credentials({})["credentials"]
    assert len(creds2) == 1
    assert creds2[0]["rpId"] == "service.com"
    assert creds2[0]["username"] == "Charlie"
