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
| `ping` | (none) | `{"status": "ok", "version": "1.0.0"}` |
| `vault_exists` | (none) | `{"exists": bool}` |
| `create_vault` | `{"password": str}` | `{"recovery_key": str}` |
| `unlock` | `{"password": str}` | `{"success": bool, "credential_count": int}` |
| `lock` | (none) | `{"success": true}` |
| `is_unlocked` | (none) | `{"unlocked": bool}` |
| `create_credential` | `{"options": ..., "origin": str}` | `{"credential": {...}}` |
| `get_assertion` | `{"options": ..., "origin": str}` | `{"assertion": {...}}` or `{"candidates": [...]}` |
| `list_credentials` | `{"domain"?: str}` | `{"credentials": [...]}` |
| `get_settings` | (none) | `{"settings": {...}}` |
| `update_settings` | `{"settings": {...}}` | `{"success": true}` |

Error responses: `{"error": "message"}`

## Browser Registration

Manifest file path per OS + browser. See `manifest.py` for exact paths.
