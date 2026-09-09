# Native Messaging Protocol

## Transport

Chrome/Edge/Firefox native messaging over stdio. Each message is `<4-byte uint32 LE length><UTF-8 JSON payload>`.

Max message size: 1 MB.

## Message Format

Every request:
```json
{"requestId": <int>, "action": "<string>", ...}
```

Every response echoes `requestId` back.

## Actions

| Action | Request fields | Response fields |
|--------|---------------|-----------------|
| `ping` | (none) | `{"status": "ok", "version": "1.1.0"}` |
| `vault_exists` | (none) | `{"exists": bool}` |
| `create_vault` | `{"password": str}` | `{"recovery_key": str}` |
| `unlock` | `{"password": str}` | `{"success": bool, "credential_count": int}` |
| `lock` | (none) | `{"success": true}` |
| `is_unlocked` | (none) | `{"unlocked": bool}` |
| `create_credential` | `{"options": ..., "origin": str}` | `{"credential": {...}}` |
| `get_assertion` | `{"options": ..., "origin": str}` | `{"credential": {...}}` |
| `recover_vault` | `{"recoveryKey": str, "newPassword": str}` | `{"success": true}` |
| `list_credentials` | `{"domain"?: str}` | `{"credentials": [...]}` |
| `delete_credential` | `{"credentialId": str}` | `{"success": true}` |
| `get_settings` | (none) | `{"settings": {...}}` |
| `update_settings` | `{"settings": {...}}` | `{"success": true}` |

Error responses: `{"error": "message", "errorCode": "ZP-Exxx", "support": "zenithprojects@icloud.com"}`

## Origin Trust

The host validates that the `origin` matches the claimed `rpId` for every
WebAuthn ceremony. The extension derives `origin` from the sender tab's URL
(`sender.url`) — never from message contents.

## Cross-Process Lock

The CLI writes a `lock-requested` sentinel file in the vault directory; the
host polls for it and clears its in-memory session, then writes `lock-ack`.
This makes `zenith-passkeys lock` lock the live browser session.

## Browser Registration

Manifest file path per OS + browser. See `manifest.py` for exact paths.
For unpacked (dev) extension installs, register the actual extension ID:

```bash
zenith-passkeys init --extension-id <32-char-id-from-chrome://extensions>
```
