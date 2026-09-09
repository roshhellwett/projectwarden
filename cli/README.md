# Zenith Passkeys (`zenithpasskeys`)

[![PyPI version](https://img.shields.io/pypi/v/zenithpasskeys.svg)](https://pypi.org/project/zenithpasskeys/)
[![Python versions](https://img.shields.io/pypi/pyversions/zenithpasskeys.svg)](https://pypi.org/project/zenithpasskeys/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

> **Local-first, air-gapped passkey (WebAuthn & FIDO2) manager with an encrypted vault.**  
> Built and managed by **Zenith Open Source Projects**.

---

## Highlights

- 🔒 **100% Local-First & Air-Gapped:** Zero cloud accounts, zero telemetry, zero external network requests. Your private keys never touch the internet.
- 🛡️ **Hardware-Grade Cryptography:** Master Encryption Key (MEK) protected by **Argon2id** (64MB RAM, 3 iterations, 4 lanes) and **AES-256-GCM** authenticated encryption.
- 🔑 **Dual-Slot Emergency Recovery:** Instant vault recovery using a 32-character Crockford Base32 emergency key (`XXXX-XXXX-...`). Re-wraps the MEK under a new password without losing any passkeys.
- ⚡ **Zero Setup Required:** Runs out of the box in any environment without manual virtualenv activation or system compilation.
- 🌐 **Dual Standalone or Browser Mode:** Use purely from the terminal as an independent passkey vault, or pair seamlessly with the Zenith Passkeys Chrome/Edge/Firefox Web Extension.

---

## Installation

Install in any environment via `pip`:

```bash
pip install zenithpasskeys
```

Or install cleanly using `pipx` (recommended for isolated CLI tools with zero venv management):

```bash
pipx install zenithpasskeys
```

Once installed, you can launch the CLI using either command:

```bash
zenith-passkeys
# or
zenithpasskeys
```

---

## Quickstart Guide

### 1. Initialize Your Secure Vault
Create a new encrypted vault and generate your 32-character Emergency Recovery Key:

```bash
zenith-passkeys init
```

Save the printed recovery key in a physical notebook or cold storage.

### 2. View Stored Passkeys
List all passkey credentials stored in your local vault:

```bash
zenith-passkeys list

# Filter by domain:
zenith-passkeys list --domain github.com
```

### 3. Run a Security Audit
Perform an offline diagnostic check for duplicate credentials or stale passkeys:

```bash
zenith-passkeys audit
```

### 4. Export & Import Credentials
Securely export your credentials (encrypted with a dedicated export password):

```bash
# Encrypted export (recommended):
zenith-passkeys export --encrypt

# Plaintext export:
zenith-passkeys export
```

Import credentials from another Zenith instance or migration file:

```bash
zenith-passkeys import export.json
```

### 5. Create Local Backup Snapshots
Create an encrypted backup snapshot directly to an external drive, USB stick, or backup directory:

```bash
zenith-passkeys backup create /path/to/backup/zenith-vault-backup.enc
```

### 6. Emergency Recovery
Forgot your master password? Recover your vault and set a new password using your Emergency Recovery Key:

```bash
zenith-passkeys recover
```

### 7. Instant Lock
Clear active authentication sessions and lock the vault across all processes:

```bash
zenith-passkeys lock
```

---

## Command Reference

| Command | Description |
|---|---|
| `zenith-passkeys init` | Initialize a new vault and register native host messaging |
| `zenith-passkeys list` | Display stored passkeys with rich metadata and domain filtering |
| `zenith-passkeys audit` | Run offline security diagnostics and health scoring |
| `zenith-passkeys export` | Export credentials to encrypted or plaintext JSON |
| `zenith-passkeys import` | Import credentials from encrypted or plaintext export files |
| `zenith-passkeys backup` | Create or restore encrypted vault backup snapshots |
| `zenith-passkeys recover` | Reset master password using 32-character Emergency Recovery Key |
| `zenith-passkeys rotate-recovery-key` | Generate and display a new active Emergency Recovery Key |
| `zenith-passkeys change-password` | Update master password and re-wrap vault master key |
| `zenith-passkeys lock` | Clear active memory session and lock the vault |
| `zenith-passkeys config` | Configure auto-lock timeout (inactivity minutes) |
| `zenith-passkeys delete` | Permanently delete a credential by domain |
| `zenith-passkeys logs` | View internal diagnostic action audit trail |

---

## Pairing with the Browser Extension (Optional)

Zenith Passkeys works as a standalone terminal manager, but also pairs with the **Zenith Passkeys Browser Extension** for passwordless web logins.

When you run:

```bash
zenith-passkeys init
```

it automatically writes the Native Messaging manifest for Google Chrome, Microsoft Edge, and Mozilla Firefox. The browser extension can then securely communicate with the local `zenith-passkeys-host` daemon to sign WebAuthn ceremonies on sites like GitHub, Google, and Amazon.

---

## Security Architecture

1. **Argon2id Key Derivation:**
   - Memory: 64 MB (`m=65536`)
   - Iterations: 3 (`t=3`)
   - Parallelism: 4 lanes (`p=4`)
2. **Dual-Slot Key Wrapping:**
   - Slot 0 (`pwWrapped`): Master Encryption Key encrypted under master password.
   - Slot 1 (`recWrapped`): Master Encryption Key encrypted under the 32-character recovery key.
   - Password changes re-wrap Slot 0 while keeping the recovery key permanently functional.
3. **Atomic Operations & Integrity:**
   - Atomic file replace using tempfile swaps to eliminate corruption risks.
   - File locks via `filelock` prevent concurrent write race conditions.
   - Public Suffix List (PSL) validation prevents cross-subdomain credential spoofing.

---

## License & Support

- **License:** Open source under the [MIT License](https://opensource.org/licenses/MIT).
- **Repository:** [GitHub](https://github.com/roshhellwett/projectwarden)
- **Support & Security Disclosures:** `zenithprojects@icloud.com`
- **Maintained by:** **Zenith Open Source Projects**
