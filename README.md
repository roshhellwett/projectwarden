# Zenith Passkeys

Local-first passkey (WebAuthn/FIDO2) manager with encrypted vault.

## Architecture

- **Python CLI** (`zenith-passkeys`) — manage passkeys from terminal
- **Browser Extension** — intercepts WebAuthn calls, stores passkeys locally
- **Native Messaging Host** — Python process that bridges extension ↔ vault file
- **Encrypted vault** — single `vault.enc` file using Argon2id + AES-256-GCM

## Quick Start

```bash
pip install zenith-passkeys
zenith-passkeys init
zenith-passkeys list
```

Load `extension/` as unpacked extension in Chrome/Edge/Firefox.

## Commands

- `init` — create or recover a vault
- `list` — list stored credentials
- `export` / `import` — backup/restore credentials
- `audit` — check for security issues
- `config` — update settings
- `lock` — lock vault
- `backup push/pull` — cloud backup

## License

MIT
