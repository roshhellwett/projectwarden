import time
import gc
from ..core.vault import VaultManager
from ..core.schema import VaultPayload
from ..core.credentials import add_credential, find_credentials, update_counter
from ..core.webauthn import create_credential_response, get_assertion_response, base64url_decode
from .protocol import read_message, send_message

class NativeHost:
    def __init__(self):
        self.vault = VaultManager()
        self.payload: VaultPayload | None = None
        self.mek: bytes | None = None
        self.last_activity = time.time()
        self.idle_timeout = 900

    def run(self):
        try:
            while True:
                msg = read_message()
                if msg is None:
                    break
                self._check_idle()
                self.last_activity = time.time()
                resp = self._dispatch(msg)
                resp["requestId"] = msg.get("requestId")
                send_message(resp)
        except Exception as e:
            import traceback, base64
            tb = traceback.format_exc()
            error_code = base64.b64encode(tb.encode("utf-8")).decode("utf-8")
            try:
                send_message({"error": "Fatal host error", "errorCode": error_code})
            except Exception:
                pass

    def _check_idle(self):
        if self.mek and (time.time() - self.last_activity > self.idle_timeout):
            self._lock()

    def _lock(self):
        self.payload = None
        self.mek = None
        gc.collect()

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
                "list_credentials": self._list_credentials,
                "get_settings": self._get_settings,
                "update_settings": self._update_settings,
            }.get(action)
            if not handler:
                return {"error": f"Unknown action: {action}"}
            return handler(msg)
        except Exception as e:
            import traceback, base64
            tb = traceback.format_exc()
            error_code = base64.b64encode(tb.encode("utf-8")).decode("utf-8")
            return {"error": str(e), "errorCode": error_code}

    def _ping(self, msg): return {"status": "ok", "version": "1.0.0"}
    def _vault_exists(self, msg): return {"exists": self.vault.exists()}
    def _is_unlocked(self, msg): return {"unlocked": self.mek is not None}

    def _create_vault(self, msg):
        password = msg.get("password", "")
        recovery_display, mek = self.vault.create(password)
        self.payload = VaultPayload()
        self.mek = mek
        return {"recovery_key": recovery_display}

    def _unlock(self, msg):
        password = msg.get("password", "")
        self.payload, self.mek = self.vault.unlock(password)
        return {"success": True, "credential_count": len(self.payload.credentials)}

    def _do_lock(self, msg):
        self._lock()
        return {"success": True}

    def _create_credential(self, msg):
        if not self.mek:
            return {"error": "Vault is locked"}
        options = msg.get("options", {})
        origin = msg.get("origin", "")
        rp_id = options.get("rp", {}).get("id", "")
        challenge = options.get("challenge", "")
        user = options.get("user", {})
        user_handle = base64url_decode(user.get("id", ""))
        username = user.get("displayName", user.get("name", ""))

        response, cred = create_credential_response(rp_id, origin, challenge, user_handle, username)
        self.payload = add_credential(self.payload, cred)
        self.vault.save(self.payload, self.mek)
        return {"credential": response}

    def _get_assertion(self, msg):
        if not self.mek:
            return {"error": "Vault is locked"}
        options = msg.get("options", {})
        origin = msg.get("origin", "")
        rp_id = options.get("rpId", "")
        challenge = options.get("challenge", "")
        allow_list = None
        if "allowCredentials" in options:
            allow_list = [c.get("id", "") for c in options["allowCredentials"]]

        candidates = find_credentials(self.payload, rp_id, allow_list)
        if not candidates:
            return {"error": f"No credentials found for {rp_id}"}
        if len(candidates) > 1:
            return {"candidates": [{"credentialId": c.credential_id, "username": c.username, "rpId": c.rp_id} for c in candidates]}

        cred = candidates[0]
        response, new_counter = get_assertion_response(cred, rp_id, origin, challenge)
        self.payload = update_counter(self.payload, cred.credential_id, new_counter)
        self.vault.save(self.payload, self.mek)
        return {"assertion": response}

    def _list_credentials(self, msg):
        if not self.mek:
            return {"error": "Vault is locked"}
        domain = msg.get("domain")
        creds = self.payload.credentials
        if domain:
            creds = [c for c in creds if c.rp_id == domain]
        return {"credentials": [
            {"rpId": c.rp_id, "username": c.username, "credentialId": c.credential_id,
             "createdAt": c.created_at, "lastUsedAt": c.last_used_at}
            for c in creds
        ]}

    def _get_settings(self, msg):
        if not self.mek:
            return {"error": "Vault is locked"}
        from dataclasses import asdict
        return {"settings": asdict(self.payload.settings)}

    def _update_settings(self, msg):
        if not self.mek:
            return {"error": "Vault is locked"}
        updates = msg.get("settings", {})
        for key, value in updates.items():
            if hasattr(self.payload.settings, key):
                setattr(self.payload.settings, key, value)
        self.vault.save(self.payload, self.mek)
        return {"success": True}

def main():
    host = NativeHost()
    host.run()
