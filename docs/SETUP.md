# Setup Guide

Detailed platform-specific setup instructions for Zenith Passkeys.

## Prerequisites

- **Python 3.10+** installed and available on your PATH
- **pip** package manager
- **Chrome**, **Edge**, or **Firefox** browser

## Step 1: Install the CLI

```bash
# From the project root directory
pip install -e ./cli
```

Verify the installation:

```bash
zenith-passkeys --version
# Should output: zenith-passkeys, version 1.1.0
```

## Step 2: Create Your Vault

```bash
zenith-passkeys init
```

You will be prompted to:
1. Set a **master password** (minimum 8 characters)
2. A **recovery key** will be displayed — **write it down and store it securely**

> ⚠️ **IMPORTANT:** If you lose both your master password and recovery key, your passkeys are gone forever. There is no way to recover them.

The vault file is stored at:
- **Windows:** `%APPDATA%\zenith-passkeys\zenith-passkeys\vault.enc` (per platformdirs; shown by the CLI on request)
- **macOS:** `~/Library/Application Support/zenith-passkeys/vault.enc`
- **Linux:** `~/.config/zenith-passkeys/vault.enc`

## Step 3: Load the Browser Extension

### Chrome / Edge

1. Open `chrome://extensions` (Chrome) or `edge://extensions` (Edge)
2. Enable **Developer mode** using the toggle in the top-right
3. Click **Load unpacked**
4. Navigate to the `extension/` folder inside this project and select it
5. The extension will appear in your toolbar with the Zenith "Z" logo icon
6. Copy the **Extension ID** shown under the extension name (32 characters, a-p)

### Firefox

1. Open `about:debugging#/runtime/this-firefox`
2. Click **Load Temporary Add-on...`
3. Navigate to `extension/manifest.json` and select it
4. The extension will appear in your toolbar

> ℹ️ **Note:** Firefox temporary extensions are removed when you close the browser. For persistent installation, sign the extension through Mozilla's addon system.

## Step 4: Register the Native Host with YOUR Extension ID

The native host only accepts messages from the allow-listed extension ID.
Unpacked/dev extensions get a per-machine ID, so pass it to init:

```bash
zenith-passkeys init --extension-id <your-32-char-extension-id>
```

This writes the ID to the native messaging manifests and the Windows
registry. `init` re-run without the flag keeps your saved ID.

If the popup says "Native host not connected", this is the first thing to
check — a mismatched extension ID is the most common cause.

## Step 5: Daily Use

- **Unlock**: click the extension icon, enter your master password
- **Sign in / register**: visit any passkey-supporting site; a Zenith
  confirmation window appears — Allow (optionally unlock) and the ceremony completes
- **Lock**: popup → Settings → 🔒 Lock Vault, or CLI `zenith-passkeys lock`
  (both clear the live session)
- **Recover**: forgot your password? Popup → "Forgot password? Use Recovery
  Key", or CLI `zenith-passkeys init --recover`

## Troubleshooting

### Native host won't connect

1. **Check the extension ID matches:**
   ```bash
   zenith-passkeys init --extension-id <id-from-chrome://extensions>
   ```
2. **Check the manifest exists** (Windows):
   `%LOCALAPPDATA%\zenith-passkeys\native-manifests\chrome\com.zenith.passkeys.json` —
   its `allowed_origins` must contain your extension ID.
3. **Check the host executable:**
   ```bash
   where zenith-passkeys-host   # Windows
   which zenith-passkeys-host   # Linux/macOS
   ```
   If not found, reinstall: `pip install -e ./cli`
4. **Check the browser console:** open the extension's service worker (from
   `chrome://extensions`) and check for errors.

### Vault file permissions

The vault file should only be readable by your user:
- **Linux/macOS:** `chmod 600 ~/.config/zenith-passkeys/vault.enc`
- **Windows:** File permissions are set automatically

### Browser-only (fallback) mode

If the native host isn't available, the extension runs in **fallback mode**:
- Uses PBKDF2 (600k iterations) instead of Argon2id for key derivation
- Stores credentials in `chrome.storage.local` (encrypted)
- Produces spec-conformant WebAuthn structures (CBOR attestation, DER signatures)
- Vaults created in fallback mode are **not compatible** with the CLI vault format
- To migrate: export from fallback mode, then import into the CLI vault

### Something else broke

Every error surface shows a short **error code** — copy it and email
**zenithprojects@icloud.com**.

### Local Vault Backup (USB / Air-Gapped)

Zenith Passkeys is 100% local-first and does not transmit your vault to the cloud. You have full freedom to save encrypted backups directly to a USB pendrive, external drive, or local folder:

```bash
# Create an encrypted backup on a USB pendrive
zenith-passkeys backup create E:\my-vault-backup.enc

# Restore from an encrypted backup (verified in-memory before replacing local vault)
zenith-passkeys backup restore E:\my-vault-backup.enc
```

> ℹ️ The backup file is encrypted with Argon2id and AES-256-GCM. It is safe to store on cold storage or portable drives. `backup restore` cryptographically validates that the file decrypts with your master password before touching your local vault.
