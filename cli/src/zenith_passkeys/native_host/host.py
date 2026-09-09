import gc
import time

from ..core.credentials import (
    add_credential,
    delete_credential,
    find_credentials,
    update_counter,
)
from ..core.errors import ERR_RECOVERY, SUPPORT_EMAIL, error_payload
from ..core.psl import validate_rp_id
from ..core.recovery import parse_recovery_key
from ..core.schema import VaultPayload
from ..core.vault import VaultManager
from ..core.webauthn import (
    base64url_decode,
    create_credential_response,
    get_assertion_response,
)
from .lock_sentinel import consume_lock_request, write_lock_ack
from .protocol import read_message, send_message

# Verification freshness window for the UV flag (audit F-008):
# user verification (password entry) is honored for this many seconds.
UV_FRESHNESS_SECONDS = 300


class NativeHost:
    def __init__(self):
        self.vault = VaultManager()
        self.payload: VaultPayload | None = None
        self.mek: bytearray | None = None
        self.last_activity = time.time()
        self.last_verified = 0.0  # timestamp of last password entry
        self.idle_timeout = 900

    def run(self):
        try:
            while True:
                msg = read_message()
                if msg is None:
                    break
                self._check_idle()
                self._check_lock_sentinel()
                self.last_activity = time.time()
                resp = self._dispatch(msg)
                resp["requestId"] = msg.get("requestId")
                send_message(resp)
        except Exception as e:  # noqa: BLE001 - fatal-loop handler
            try:
                send_message(error_payload(str(e), "ZP-E099"))
            except Exception:  # noqa: BLE001, S110 - fatal-loop handler must not raise
                pass

    def _check_idle(self):
        if self.mek and (time.time() - self.last_activity > self.idle_timeout):
            self._lock()

    def _check_lock_sentinel(self):
        """Honor lock requests from the CLI (cross-process)."""
        if consume_lock_request():
            self._lock()
            write_lock_ack()

    def _lock(self):
        self.payload = None
        self.last_verified = 0.0
        if self.mek is not None:
            if isinstance(self.mek, bytearray):
                self.mek[:] = b'\x00' * len(self.mek)
            self.mek = None
        gc.collect()

    def _uv_ok(self) -> bool:
        """User verification is fresh if a password was entered recently."""
        return (time.time() - self.last_verified) <= UV_FRESHNESS_SECONDS

    @staticmethod
    def _uv_required(options: dict) -> bool:
        """Did the RP require user verification for this ceremony?

        WebAuthn default is 'preferred'; 'required' means the RP will
        reject an assertion whose flags do not carry UV.
        """
        return str(options.get("userVerification") or "preferred").lower() == "required"

    def _dispatch(self, msg: dict) -> dict:
        action = msg.get("action", "")
        try:
            handler = {
                "ping": self._ping,
                "vault_exists": self._vault_exists,
                "create_vault": self._create_vault,
                "unlock": self._unlock,
                "lock": self._do_lock,
                "is_unlocked": self._is_unlocked,
                "create_credential": self._create_credential,
                "get_assertion": self._get_assertion,
                "recover_vault": self._recover_vault,
                "list_credentials": self._list_credentials,
                "get_settings": self._get_settings,
                "update_settings": self._update_settings,
                "delete_credential": self._delete_credential,
                "change_password": self._change_password,
                "get_audit_report": self._get_audit_report,
                "get_action_logs": self._get_action_logs,
                "get_backup_blob": self._get_backup_blob,
                "restore_backup_blob": self._restore_backup_blob,
                "export_vault": self._export_vault,
                "import_vault": self._import_vault,
                "rotate_recovery_key": self._rotate_recovery_key,
            }.get(action)
            if not handler:
                return {"error": f"Unknown action: {action}",
                        "support": SUPPORT_EMAIL}

            resp = handler(msg)

            if self.mek and self.payload and action in [
                "unlock", "create_credential", "get_assertion", "delete_credential",
                "recover_vault", "change_password", "restore_backup_blob", "import_vault",
            ]:
                status = "error" if "error" in resp else "success"
                details = resp.get("error", "Action successful")
                if status == "error" and isinstance(details, dict):
                    details = str(details)
                self._log_action(action, status, details)

            return resp
        except Exception as e:  # noqa: BLE001 - per-message handler
            if self.mek and self.payload:
                self._log_action(action, "error", str(e))
            return error_payload(str(e), "ZP-E098")

    def _log_action(self, action: str, status: str, details: str) -> None:
        if not self.mek or not self.payload:
            return

        def updater(p):
            from ..core.schema import LogEntry
            p.action_log.append(LogEntry(time.time(), action, status, details))
            if len(p.action_log) > 100:
                p.action_log = p.action_log[-100:]
            return p
        try:
            self.payload = self.vault.update(updater, self.mek)
        except Exception:  # noqa: BLE001, S110 - logging must never kill a ceremony
            pass

    def _ping(self, msg):
        return {"status": "ok", "version": "1.1.2"}

    def _vault_exists(self, msg):
        return {"exists": self.vault.exists()}

    def _is_unlocked(self, msg):
        return {"unlocked": self.mek is not None,
                "verified": self.mek is not None and self._uv_ok()}

    def _create_vault(self, msg):
        password = msg.get("password", "")
        recovery_display, mek = self.vault.create(password)
        self.payload = VaultPayload()
        self.mek = mek
        return {"recovery_key": recovery_display}

    def _unlock(self, msg):
        password = msg.get("password", "")
        self.payload, self.mek = self.vault.unlock(password)
        self.last_verified = time.time()
        self.idle_timeout = self.payload.settings.idle_timeout_minutes * 60
        return {"success": True, "credential_count": len(self.payload.credentials)}

    def _do_lock(self, msg):
        self._lock()
        return {"success": True}

    def _recover_vault(self, msg):
        """Recover with recovery key + set a new password (popup flow)."""
        recovery_display = msg.get("recoveryKey", "")
        new_password = msg.get("newPassword", "")
        try:
            recovery_raw = parse_recovery_key(recovery_display)
        except ValueError as e:
            return {"error": str(e), "support": SUPPORT_EMAIL, "errorCode": ERR_RECOVERY}
        try:
            self.vault.set_password_with_recovery(recovery_raw, new_password)
        except ValueError as e:
            return {"error": str(e), "support": SUPPORT_EMAIL, "errorCode": ERR_RECOVERY}
        self.payload, self.mek = self.vault.unlock(new_password)
        self.last_verified = time.time()
        return {"success": True}

    def _validate_rp_id(self, rp_id: str, origin: str) -> bool:
        if not rp_id:
            # Empty rpId defaults to the origin's hostname (audit F-010)
            from urllib.parse import urlparse
            rp_id = urlparse(origin).hostname or ""
        return validate_rp_id(rp_id, origin)

    @staticmethod
    def _effective_rp_id(options: dict, origin: str) -> str:
        rp_id = options.get("rp", {}).get("id", "") if "rp" in options else options.get("rpId", "")
        return rp_id or _hostname_of(origin)

    def _create_credential(self, msg):
        if not self.mek:
            return {"error": "Vault is locked"}
        options = msg.get("options", {})
        origin = msg.get("origin", "")
        if not origin:
            return {"error": "Missing origin"}
        rp_id = options.get("rp", {}).get("id", "") or _hostname_of(origin)
        if not self._validate_rp_id(rp_id, origin):
            return {"error": f"Security Error: Invalid rpId {rp_id} for origin {origin}"}

        challenge = options.get("challenge", "")
        user = options.get("user", {})
        try:
            user_handle = base64url_decode(user.get("id", ""))
        except Exception:  # noqa: BLE001
            user_handle = b""

        username = user.get("displayName", user.get("name", ""))

        response, cred = create_credential_response(
            rp_id, origin, challenge, user_handle, username, uv=self._uv_ok()
        )

        def updater(p):
            return add_credential(p, cred)

        self.payload = self.vault.update(updater, self.mek)
        return {"credential": response}

    def _get_assertion(self, msg):
        if not self.mek:
            return {"error": "Vault is locked"}
        options = msg.get("options", {})
        origin = msg.get("origin", "")
        if not origin:
            return {"error": "Missing origin"}
        rp_id = options.get("rpId", "") or _hostname_of(origin)
        if not self._validate_rp_id(rp_id, origin):
            return {"error": f"Security Error: Invalid rpId {rp_id} for origin {origin}"}
        challenge = options.get("challenge", "")
        allow_list = None
        if "allowCredentials" in options:
            allow_list = [c.get("id", "") for c in options["allowCredentials"]]

        candidates = find_credentials(self.payload, rp_id, allow_list)
        if not candidates:
            return {"error": f"No credentials found for {rp_id}"}

        # If the RP REQUIRED user verification and our verification is stale,
        # ask the extension to re-verify (password prompt) before signing.
        # Signing with UV=0 would just get the assertion rejected (e.g. GitHub).
        if self._uv_required(options) and not self._uv_ok():
            return {"needs_verification": True}

        # excludeCredentials is a SHOULD in WebAuthn: if RP lists exclusions,
        # prefer a credential not in the exclude list.
        exclude_ids = set()
        if "excludeCredentials" in options:
            exclude_ids = {c.get("id", "") for c in options["excludeCredentials"]}

        selected_id = options.get("selectedCredentialId")
        if selected_id:
            matching = [c for c in candidates if c.credential_id == selected_id]
            if matching:
                cred = matching[0]
            else:
                cred = candidates[-1]
        else:
            cred = candidates[-1]
            if cred.credential_id in exclude_ids and len(candidates) > 1:
                others = [c for c in candidates if c.credential_id not in exclude_ids]
                if others:
                    cred = others[-1]

        # Reached here only if UV was not required, or is still fresh:
        # either way _uv_ok() reports the flag honestly.
        response, new_counter = get_assertion_response(
            cred, rp_id, origin, challenge, uv=self._uv_ok()
        )

        def updater(p):
            return update_counter(p, cred.credential_id, new_counter)

        self.payload = self.vault.update(updater, self.mek)
        return {"credential": response}

    def _list_credentials(self, msg):
        if not self.mek:
            return {"error": "Vault is locked"}
        domain = msg.get("domain")
        creds = self.payload.credentials
        if domain:
            creds = [c for c in creds if c.rp_id == domain or domain.endswith("." + c.rp_id)]
        return {"credentials": [
            {"rpId": c.rp_id, "username": c.username, "credentialId": c.credential_id,
             "createdAt": c.created_at, "lastUsedAt": c.last_used_at}
            for c in creds
        ]}

    def _delete_credential(self, msg):
        if not self.mek:
            return {"error": "Vault is locked"}
        credential_id = msg.get("credentialId", "")
        if not credential_id:
            return {"error": "Missing credentialId"}
        try:
            def updater(p):
                return delete_credential(p, credential_id)
            self.payload = self.vault.update(updater, self.mek)
            return {"success": True}
        except ValueError as e:
            return {"error": str(e)}

    def _get_settings(self, msg):
        if not self.mek:
            return {"error": "Vault is locked"}
        from dataclasses import asdict
        return {"settings": asdict(self.payload.settings)}

    def _update_settings(self, msg):
        if not self.mek:
            return {"error": "Vault is locked"}
        updates = msg.get("settings", {})

        def updater(p):
            import copy
            old_settings = copy.deepcopy(p.settings)
            for key, value in updates.items():
                if key.startswith("_"):
                    continue
                if hasattr(p.settings, key):
                    setattr(p.settings, key, value)
            try:
                p.settings.validate()
            except ValueError as e:
                p.settings = old_settings
                raise ValueError(str(e)) from None
            return p

        try:
            self.payload = self.vault.update(updater, self.mek)
            self.idle_timeout = self.payload.settings.idle_timeout_minutes * 60
            return {"success": True}
        except ValueError as e:
            return {"error": str(e)}

    def _change_password(self, msg):
        if not self.mek:
            return {"error": "Vault is locked"}
        old_pw = msg.get("oldPassword", "")
        new_pw = msg.get("newPassword", "")
        if not old_pw or not new_pw:
            return {"error": "Missing old or new password"}
        if len(new_pw) < 8:
            return {"error": "New password must be at least 8 characters"}
        try:
            self.vault.change_password(old_pw, new_pw)
            self.payload, self.mek = self.vault.unlock(new_pw)
            self.last_verified = time.time()
            return {"success": True}
        except ValueError as e:
            return {"error": str(e)}

    def _rotate_recovery_key(self, msg):
        if not self.mek:
            return error_payload("Vault is locked", "ZP-E001")
        try:
            display_rec = self.vault.rotate_recovery_key(self.mek)
            return {"success": True, "recovery_key": display_rec}
        except Exception as e:
            return error_payload(str(e), ERR_RECOVERY)

    def _get_audit_report(self, msg):
        if not self.mek:
            return {"error": "Vault is locked"}
        from datetime import datetime, timezone
        unused_days = int(msg.get("unusedDays", 90))
        now = datetime.now(timezone.utc)
        issues = []

        for c in self.payload.credentials:
            if c.last_used_at:
                try:
                    last = datetime.fromisoformat(c.last_used_at)
                    diff = (now - last).days
                    if diff >= unused_days:
                        issues.append({
                            "type": "stale",
                            "severity": "low",
                            "rpId": c.rp_id,
                            "username": c.username,
                            "credentialId": c.credential_id,
                            "detail": f"Not used in {diff} days"
                        })
                except ValueError:
                    pass

        seen = {}
        for c in self.payload.credentials:
            key = (c.rp_id, c.username)
            if key in seen:
                issues.append({
                    "type": "duplicate",
                    "severity": "medium",
                    "rpId": c.rp_id,
                    "username": c.username,
                    "credentialId": c.credential_id,
                    "detail": "Multiple passkeys registered for same account"
                })
            seen[key] = True

        total = len(self.payload.credentials)
        deduction = len([i for i in issues if i["severity"] == "low"]) * 5 + len([i for i in issues if i["severity"] == "medium"]) * 15
        score = max(0, 100 - deduction) if total > 0 else 100
        grade = "A" if score >= 90 else ("B" if score >= 75 else ("C" if score >= 60 else "D"))
        return {
            "issues": issues,
            "healthScore": score,
            "grade": grade,
            "totalCredentials": total
        }

    def _get_action_logs(self, msg):
        if not self.mek:
            return {"error": "Vault is locked"}
        from datetime import datetime, timezone
        logs = []
        for e in reversed(self.payload.action_log or []):
            try:
                iso_ts = datetime.fromtimestamp(e.timestamp, tz=timezone.utc).isoformat()
            except Exception:
                iso_ts = str(e.timestamp)
            logs.append({
                "timestamp": e.timestamp,
                "iso_timestamp": iso_ts,
                "action": e.action,
                "status": e.status,
                "details": e.details,
            })
        return {"logs": logs}

    def _get_backup_blob(self, msg):
        if not self.mek:
            return {"error": "Vault is locked"}
        import base64
        import hashlib
        from datetime import datetime, timezone
        with self.vault.lock:
            blob = self.vault.vault_path.read_bytes()
        b64 = base64.b64encode(blob).decode("ascii")
        sha = hashlib.sha256(blob).hexdigest()
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M%S")
        return {
            "backupBlob": b64,
            "sha256": sha,
            "size": len(blob),
            "credentialCount": len(self.payload.credentials),
            "filename": f"zenith-vault-backup-{ts}.enc"
        }

    def _restore_backup_blob(self, msg):
        import base64
        from ..core.crypto import VaultHeader, decrypt_aes_gcm, derive_key
        b64 = msg.get("backupBlob", "")
        password = msg.get("password", "")
        if not b64 or not password:
            return {"error": "Missing backup file data or password"}
        try:
            blob = base64.b64decode(b64)
        except Exception:
            return {"error": "Invalid base64 backup data"}

        try:
            header = VaultHeader.from_bytes(blob)
            if len(blob) < header.size() + 16:
                return {"error": "Backup file is too small or truncated"}
        except Exception:
            return {"error": "Invalid backup file: not a valid Zenith Passkeys vault"}

        # Pre-flight test in memory
        try:
            dk = derive_key(password.encode(), header.pw_salt, header.kdf_iterations, header.kdf_memory, header.kdf_lanes)
            aad = header.aad() if header.version >= 2 else None
            mek_test = decrypt_aes_gcm(header.pw_wrapped_mek, dk, header.pw_wrapped_nonce, aad)
            payload_ct = blob[header.size():]
            payload_json = decrypt_aes_gcm(payload_ct, mek_test, header.payload_nonce, aad)
            VaultPayload.from_json(payload_json)
        except Exception:
            return {"error": "Password does not unlock this backup file. Local vault was not touched."}

        # Safe transactional replace with rollback snapshot
        with self.vault.lock:
            if self.vault.exists():
                bak_path = self.vault.vault_path.with_suffix(".enc.bak")
                try:
                    import shutil
                    shutil.copy2(str(self.vault.vault_path), str(bak_path))
                except Exception:
                    pass
            self.vault._atomic_write(blob)

        self.payload, self.mek = self.vault.unlock(password)
        self.last_verified = time.time()
        self.idle_timeout = self.payload.settings.idle_timeout_minutes * 60
        return {"success": True, "credentialCount": len(self.payload.credentials)}

    def _export_vault(self, msg):
        if not self.mek:
            return {"error": "Vault is locked"}
        import json
        from datetime import datetime, timezone
        export_pw = msg.get("password")
        export_data = {
            "version": 1,
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "credentials": [
                {
                    "rp_id": c.rp_id,
                    "credential_id": c.credential_id,
                    "private_key": c.private_key,
                    "public_key": c.public_key,
                    "user_handle": c.user_handle,
                    "username": c.username,
                    "counter": c.counter,
                    "algorithm": c.algorithm,
                }
                for c in self.payload.credentials
            ],
        }
        json_bytes = json.dumps(export_data, indent=2).encode("utf-8")
        if export_pw:
            import base64
            import os
            from ..core.crypto import (
                DEFAULT_KDF_ITERATIONS,
                DEFAULT_KDF_LANES,
                DEFAULT_KDF_MEMORY,
                derive_key,
                encrypt_aes_gcm,
            )
            salt = os.urandom(16)
            dk = derive_key(export_pw.encode(), salt, DEFAULT_KDF_ITERATIONS, DEFAULT_KDF_MEMORY, DEFAULT_KDF_LANES)
            nonce = os.urandom(12)
            ct = encrypt_aes_gcm(json_bytes, dk, nonce)
            enc_container = {
                "format": "zenith-encrypted-export",
                "version": 1,
                "kdf": "argon2id",
                "salt": base64.b64encode(salt).decode("ascii"),
                "nonce": base64.b64encode(nonce).decode("ascii"),
                "ciphertext": base64.b64encode(ct).decode("ascii"),
            }
            return {"data": json.dumps(enc_container, indent=2), "encrypted": True, "credentialCount": len(self.payload.credentials)}
        return {"data": json_bytes.decode("utf-8"), "encrypted": False, "credentialCount": len(self.payload.credentials)}

    def _import_vault(self, msg):
        if not self.mek:
            return {"error": "Vault is locked"}
        creds_data = msg.get("credentials")
        if creds_data is None and "encrypted_export" in msg:
            enc = msg["encrypted_export"]
            pw = msg.get("password", "")
            if not pw:
                return {"error": "Password required for encrypted export"}
            try:
                import base64
                import hashlib
                import json
                from ..core.crypto import (
                    DEFAULT_KDF_ITERATIONS,
                    DEFAULT_KDF_LANES,
                    DEFAULT_KDF_MEMORY,
                    decrypt_aes_gcm,
                    derive_key,
                )

                def _b64dec(s: str) -> bytes:
                    s = s.replace("-", "+").replace("_", "/")
                    s += "=" * ((4 - len(s) % 4) % 4)
                    return base64.b64decode(s)

                salt = _b64dec(enc.get("salt", ""))
                nonce = _b64dec(enc.get("nonce", ""))
                ct = _b64dec(enc.get("ciphertext", ""))
                kdf = enc.get("kdf", "")
                if kdf == "pbkdf2" or "iterations" in enc:
                    iters = int(enc.get("iterations", 600000))
                    dk = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, iters, dklen=32)
                else:
                    try:
                        dk = derive_key(
                            pw.encode("utf-8"), salt, DEFAULT_KDF_ITERATIONS, DEFAULT_KDF_MEMORY, DEFAULT_KDF_LANES
                        )
                    except Exception:
                        dk = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, 600000, dklen=32)
                pt = decrypt_aes_gcm(ct, dk, nonce)
                parsed = json.loads(pt.decode("utf-8"))
                creds_data = parsed.get("credentials", parsed if isinstance(parsed, list) else [])
            except Exception as e:
                return {"error": f"Failed to decrypt export: {e}"}

        if not isinstance(creds_data, list):
            return {"error": "Invalid credentials format: expected list of credentials"}
        from ..commands.import_cmd import _validate_credential_entry
        from ..core.credentials import add_credential
        imported_count = 0
        errors = []
        valid_creds = []
        for idx, item in enumerate(creds_data):
            try:
                c = _validate_credential_entry(item)
                valid_creds.append(c)
            except Exception as e:
                errors.append(f"Credential {idx+1}: {e}")

        if not valid_creds:
            return {"error": f"No valid credentials found. Errors: {'; '.join(errors[:3])}"}

        def updater(p):
            nonlocal imported_count
            for c in valid_creds:
                p = add_credential(p, c)
                imported_count += 1
            return p

        try:
            self.payload = self.vault.update(updater, self.mek)
            return {"success": True, "importedCount": imported_count, "totalCredentials": len(self.payload.credentials), "errors": errors}
        except Exception as e:
            return {"error": str(e)}


def _hostname_of(origin: str) -> str:
    from urllib.parse import urlparse
    return urlparse(origin).hostname or ""


def main():
    host = NativeHost()
    host.run()
