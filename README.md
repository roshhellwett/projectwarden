# Zenith Passkeys 🔑

> Local-first passkey (WebAuthn/FIDO2) manager with an encrypted vault. Your keys never leave your device.

Zenith Passkeys lets you create, store, and use passkeys (WebAuthn/FIDO2 credentials) entirely on your local machine. No cloud account required. No third-party servers. Your private keys are encrypted with AES-256-GCM and protected by Argon2id key derivation.

## Features

- 🔐 **Encrypted vault** — AES-256-GCM encryption with Argon2id KDF
- 🖥️ **Works offline** — No internet connection required
- 🌐 **Browser extension** — Chrome, Edge, and Firefox support
- 💻 **CLI tool** — Manage passkeys from your terminal
- 🔄 **Cloud backup** — Optional Google Drive backup (encrypted)
- 🔑 **Recovery key** — Recover your vault if you forget your password
- 📦 **Import/Export** — Portable credential backup and restore

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                    Browser Extension                      │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────┐  │
│  │ Content      │  │ Background   │  │ Popup UI       │  │
│  │ Script       │→ │ Service      │→ │                │  │
│  │ (intercepts  │  │ Worker       │  │ Manage vault,  │  │
│  │  WebAuthn)   │  │              │  │ view creds     │  │
│  └─────────────┘  └──────┬───────┘  └────────────────┘  │
│                          │                                │
│                   Native Messaging                        │
└──────────────────────────┼───────────────────────────────┘
                           │
                    ┌──────┴──────┐
                    │ Native Host │ (Python process)
                    │             │
                    │ ┌─────────┐ │
                    │ │ Vault   │ │ ← vault.enc (AES-256-GCM)
                    │ │ Manager │ │
                    │ └─────────┘ │
                    └─────────────┘
```

## Quick Start

### 1. Install the CLI

```bash
pip install -e ./cli
```

### 2. Create your vault

```bash
zenith-passkeys init
```

This will:
- Ask you to set a master password (8+ characters)
- Generate a recovery key — **save it somewhere safe!**
- Register the native messaging host for your browsers

### 3. Load the browser extension

**Chrome / Edge:**
1. Go to `chrome://extensions` (or `edge://extensions`)
2. Enable **Developer mode** (toggle in top-right)
3. Click **Load unpacked**
4. Select the `extension/` folder from this project
5. Note your extension ID (shown under the extension name)

**Firefox:**
1. Go to `about:debugging#/runtime/this-firefox`
2. Click **Load Temporary Add-on**
3. Select `extension/manifest.json`

### 4. Configure the extension ID

After loading the extension, you need to update the native host manifest with your extension's ID:

```bash
# Re-run init to re-register the native host
zenith-passkeys init
```

> **Note:** See [docs/SETUP.md](docs/SETUP.md) for detailed platform-specific instructions and troubleshooting.

## CLI Commands

| Command | Description |
|---------|-------------|
| `zenith-passkeys init` | Create a new vault or register native host |
| `zenith-passkeys init --recover` | Recover vault using recovery key |
| `zenith-passkeys list` | List stored credentials |
| `zenith-passkeys list --json-output` | List credentials as JSON |
| `zenith-passkeys list --domain example.com` | Filter by domain |
| `zenith-passkeys export --out backup.enc --password` | Export credentials (encrypted) |
| `zenith-passkeys export --out backup.json` | Export credentials (plaintext) |
| `zenith-passkeys import backup.enc` | Import credentials from export |
| `zenith-passkeys delete example.com` | Delete a credential |
| `zenith-passkeys change-password` | Change master password |
| `zenith-passkeys audit` | Check for security issues |
| `zenith-passkeys config --idle-timeout 30` | Set idle timeout |
| `zenith-passkeys config --use-keyring` | Store password in OS keyring |
| `zenith-passkeys backup push` | Push vault to Google Drive |
| `zenith-passkeys backup pull` | Pull vault from Google Drive |
| `zenith-passkeys lock` | Lock the vault |

## Security

- **Encryption:** AES-256-GCM with Argon2id key derivation (3 iterations, 64MB memory)
- **Key hierarchy:** Master password → Argon2id → wrapping key → AES-GCM wraps MEK
- **Recovery:** Independent recovery key wraps the same MEK
- **Private keys:** Never logged, printed, or transmitted over the network
- **File writes:** Atomic (`.tmp` + `os.replace()`) to prevent corruption

See [docs/SECURITY.md](docs/SECURITY.md) for the full threat model.

## Development

```bash
# Install in development mode
pip install -e ./cli[dev]

# Run tests
pytest cli/tests/ -v

# Lint
ruff check cli/src/
```

See [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) for the full development guide.

## Troubleshooting

### "Native host not connected" in the extension popup
- Run `zenith-passkeys init` to register the native host
- Make sure the extension ID in the native host manifest matches your actual extension ID
- Check `chrome://extensions` to verify the extension is loaded

### "Wrong password" on unlock
- Make sure you're entering the correct master password
- If you forgot your password, use `zenith-passkeys init --recover` with your recovery key

### Extension shows "Browser-only mode"
- The native host isn't installed or connected
- Run `pip install -e ./cli` and then `zenith-passkeys init`
- Credentials created in browser-only mode use PBKDF2 instead of Argon2id and are stored in browser storage

## License

MIT
