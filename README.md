# Zenith Passkeys 🔑

[![PyPI](https://img.shields.io/pypi/v/zenithpasskeys.svg)](https://pypi.org/project/zenithpasskeys/)
[![Python Versions](https://img.shields.io/pypi/pyversions/zenithpasskeys.svg)](https://pypi.org/project/zenithpasskeys/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **Zenith Passkeys** is built and managed by **Zenith Open Source Projects**.  
> Local-first WebAuthn & FIDO2 passkey manager with an encrypted vault. Your keys never leave your device.

Zenith Passkeys lets you create, store, and use passkeys (WebAuthn/FIDO2 credentials) entirely on your local machine. **Zero cloud accounts. Zero third-party servers. Zero internet exposure.** Your private keys are encrypted locally with AES-256-GCM and protected by Argon2id key derivation.

---

## Features

- 🔐 **Encrypted local vault** — AES-256-GCM AEAD encryption with Argon2id KDF (3 iterations, 64MB memory)
- 🖥️ **100% Local & Air-Gapped** — No cloud servers, no telemetry, no tracking cookies. Private keys never touch the internet
- 💾 **Medium-Agnostic Local Backup** — Back up directly to a USB pendrive, external drive, or folder with atomic writes (`.tmp` + `os.fsync` + `os.replace`)
- 🛡️ **Pre-Flight Decryption Safety** — Backups are tested with your master password in an isolated staging memory sandbox before touching your active local vault
- 🌐 **Browser extension** — Chrome Web Store, Edge, and Firefox support
- 💻 **CLI tool** — Powerful terminal management (`list`, `audit`, `export`, `import`, `backup`, `lock`, `recover`)
- 🔑 **Independent recovery key** — Dedicated `recover` command to restore vault access if you forget your password (survives password changes)
- 📦 **Granular Credential Portability** — Export and import individual passkeys across machines with conflict resolution
- 🛡️ **Public Suffix List (PSL) Validation** — Built-in offline PSL validation prevents subdomain spoofing attacks
- 🛠️ **Rock-Solid Reliability** — Every failure surfaces a short actionable error code; contact `zenithprojects@icloud.com`

---

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                    Browser Extension                      │
│                 (Manifest V3, 100% Local)                │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────┐  │
│  │ Content      │  │ Background   │  │ Popup UI       │  │
│  │ Script       │→ │ Service      │→ │                │  │
│  │ (intercepts  │  │ Worker       │  │ Manage vault,  │  │
│  │ WebAuthn)    │  │              │  │ view creds     │  │
│  └─────────────┘  └──────┬───────┘  └────────────────┘  │
│                          │                                │
│                   Native Messaging (Local IPC Only)       │
└──────────────────────────┼────────────────────────────────┘
                           │
                    ┌──────┴──────┐
                    │ Native Host │ (Python daemon)
                    │             │
                    │ ┌─────────┐ │
                    │ │ Vault   │ │ ← vault.enc (Argon2id + AES-256-GCM)
                    │ │ Manager │ │
                    │ └─────────┘ │
                    └──────┬──────┘
                           │
                           ▼
          ┌──────────────────────────────────┐
          │     User's Medium of Choice      │
          │ • USB Pendrive (e.g. E:\vault)   │
          │ • Local Storage / Cold Storage   │
          │ • Password-Protected Export      │
          └──────────────────────────────────┘
```

---

## Quick Start

### 1. Install the CLI from PyPI

Install universally in any environment without needing manual venv setup:

```bash
pip install zenithpasskeys
```

Or using [pipx](https://pypa.github.io/pipx/) for an isolated global CLI environment:

```bash
pipx install zenithpasskeys
```

> **Note:** Both `zenith-passkeys` and `zenithpasskeys` are registered commands.

### 2. Create your vault

```bash
zenith-passkeys init
```

This will:
- Ask you to set a master password (8+ characters)
- Generate a 24-word recovery key — **save it somewhere safe!**
- Register the native messaging host for your browsers

### 3. Install the browser extension (Optional)

If you wish to autofill and use passkeys directly in your web browser:

**Option A: Chrome Web Store (Recommended)**
Install directly from the Chrome Web Store (published by **Zenith Open Source Projects**). Once installed, run `zenith-passkeys init` and it connects automatically!

**Option B: Unpacked Extension (Developer Mode)**
1. Go to `chrome://extensions` (or `edge://extensions`)
2. Enable **Developer mode** (toggle in top-right)
3. Click **Load unpacked** and select the `extension/` folder
4. Copy your extension ID from under the extension name and link it:
   ```bash
   zenith-passkeys init --extension-id <your-extension-id>
   ```

---

## CLI Commands

| Command | Description |
|---------|-------------|
| `zenith-passkeys init` | Create a new vault or register native host |
| `zenith-passkeys recover` | Reset master password using 32-character recovery key |
| `zenith-passkeys rotate-recovery-key` | Generate and display a new active recovery key |
| `zenith-passkeys list` | List stored passkeys |
| `zenith-passkeys list --json-output` | List credentials as JSON |
| `zenith-passkeys list --domain example.com` | Filter by domain |
| `zenith-passkeys backup create [out]` | Create atomic encrypted vault backup (USB drive or local folder) |
| `zenith-passkeys backup restore <file>` | Safely restore vault from encrypted backup (pre-flight verified) |
| `zenith-passkeys export --out backup.enc --password` | Export credentials (encrypted with separate password) |
| `zenith-passkeys export --out backup.json` | Export credentials (plaintext) |
| `zenith-passkeys import backup.enc` | Import credentials with interactive conflict resolution |
| `zenith-passkeys delete example.com` | Delete a credential |
| `zenith-passkeys change-password` | Change master password (recovery key keeps working) |
| `zenith-passkeys audit` | Security & hygiene audit (runs fully offline) |
| `zenith-passkeys audit --dns` | Also check DNS resolution (optional network check) |
| `zenith-passkeys config --idle-timeout 30` | Set auto-lock timeout in minutes |
| `zenith-passkeys lock` | Lock the vault immediately (clears browser session) |

---

## Local Backup & Air-Gapped Portability

Zenith Passkeys puts data ownership entirely in your hands:

### Backing up to a USB Pendrive
```bash
# Windows
zenith-passkeys backup create E:\my-passkeys-backup.enc

# macOS / Linux
zenith-passkeys backup create /Volumes/USB/my-passkeys-backup.enc
```

### Restoring on a New Computer
```bash
zenith-passkeys backup restore E:\my-passkeys-backup.enc
```
Before replacing any local files, Zenith performs an **in-memory pre-flight decryption check**. If the wrong password is provided, your local vault is never touched.

---

## Security

- **Encryption:** AES-256-GCM with Argon2id key derivation (3 iterations, 64MB memory)
- **Key hierarchy:** Master password → Argon2id → wrapping key → AES-GCM wraps MEK
- **Recovery:** Independent recovery key wraps the same MEK — survives password changes
- **Private keys:** Never logged, printed, or transmitted over any network
- **File writes:** Atomic (`.tmp` + `os.fsync` + `os.replace()`) with strict `0o600` permissions
- **Domain validation:** Offline Public Suffix List (PSL) prevents eTLD cross-subdomain attacks

See [docs/SECURITY.md](docs/SECURITY.md) for the full threat model.

---

## Development & Packaging

```bash
# Install in development mode
pip install -e ./cli[dev]

# Run tests
pytest cli/tests/ -v

# Lint
ruff check cli/src/

# Package extension for Chrome Web Store Developer Dashboard
python scripts/package_extension.py
```

See [docs/STORE_LISTING.md](docs/STORE_LISTING.md) for Chrome Web Store Developer Dashboard publication instructions.

---

## License & Attribution

Built and managed by **Zenith Open Source Projects**.  
Licensed under the [MIT License](LICENSE).
