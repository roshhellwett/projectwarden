# Setup Guide

Detailed platform-specific setup instructions for Zenith Passkeys.

## Prerequisites

- **Python 3.10+** installed and available in your PATH
- **pip** package manager
- **Chrome**, **Edge**, or **Firefox** browser

## Step 1: Install the CLI

```bash
# From the project root directory
pip install -e ./cli

# Or install with Google Drive backup support
pip install -e ./cli[gdrive]
```

Verify the installation:

```bash
zenith-passkeys --version
# Should output: zenith-passkeys, version 1.0.0
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
- **Windows:** `%APPDATA%\zenith-passkeys\vault.enc`
- **macOS:** `~/Library/Application Support/zenith-passkeys/vault.enc`
- **Linux:** `~/.config/zenith-passkeys/vault.enc`

## Step 3: Load the Browser Extension

### Chrome / Edge

1. Open `chrome://extensions` (Chrome) or `edge://extensions` (Edge)
2. Enable **Developer mode** using the toggle in the top-right corner
3. Click **Load unpacked**
4. Navigate to the `extension/` folder inside this project and select it
5. The extension will appear in your toolbar with a 🔑 icon

**Important:** After loading, note the **Extension ID** shown under the extension name (it looks like `abcdefghijklmnopqrstuvwxyz`). You'll need this for native host configuration.

### Firefox

1. Open `about:debugging#/runtime/this-firefox`
2. Click **Load Temporary Add-on...**
3. Navigate to `extension/manifest.json` and select it
4. The extension will appear in your toolbar

> ℹ️ **Note:** Firefox temporary extensions are removed when you close the browser. For persistent installation, you would need to sign the extension through Mozilla's addon system.

## Step 4: Configure Native Host

The `zenith-passkeys init` command automatically registers the native messaging host for Chrome, Edge, and Firefox. If you need to re-register:

```bash
zenith-passkeys init
```

### Windows Native Host Registration

On Windows, the native host manifest is registered in the Windows Registry under:
- `HKCU\Software\Google\Chrome\NativeMessagingHosts\com.zenith.passkeys`
- `HKCU\Software\Microsoft\Edge\NativeMessagingHosts\com.zenith.passkeys`
- `HKCU\Software\Mozilla\NativeMessagingHosts\com.zenith.passkeys`

The manifest files are placed in:
- `%LOCALAPPDATA%\zenith-passkeys\native-manifests\com.zenith.passkeys.json`

### macOS Native Host Registration

Manifest files are placed in:
- Chrome: `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/`
- Edge: `~/Library/Application Support/Microsoft Edge/NativeMessagingHosts/`
- Firefox: `~/Library/Application Support/Mozilla/NativeMessagingHosts/`

### Linux Native Host Registration

Manifest files are placed in:
- Chrome: `~/.config/google-chrome/NativeMessagingHosts/`
- Edge: `~/.config/microsoft-edge/NativeMessagingHosts/`
- Firefox: `~/.mozilla/native-messaging-hosts/`

## Step 5: Configure Extension ID

After loading the extension, you need to update the native host manifest with your extension's actual ID.

### Finding Your Extension ID

**Chrome/Edge:**
1. Go to `chrome://extensions` or `edge://extensions`
2. Find "Zenith Passkeys"
3. Copy the **ID** shown under the extension name

**Firefox:**
The extension ID is defined in `manifest.json` as `zenith-passkeys@zenith.dev` — no changes needed for Firefox.

### Updating the Extension ID

Open `cli/src/zenith_passkeys/native_host/manifest.py` and update the `EXTENSION_ID` constant:

```python
EXTENSION_ID = "chrome-extension://YOUR_ACTUAL_EXTENSION_ID/"
```

Then re-run:

```bash
zenith-passkeys init
```

## Troubleshooting

### Native host won't connect

1. **Check the manifest exists:**
   - Windows: Look for `%LOCALAPPDATA%\zenith-passkeys\native-manifests\com.zenith.passkeys.json`
   - Open it and verify the `path` points to a valid `zenith-passkeys-host` executable

2. **Check the host executable:**
   ```bash
   which zenith-passkeys-host  # Linux/macOS
   where zenith-passkeys-host  # Windows
   ```
   If not found, reinstall: `pip install -e ./cli`

3. **Check the extension ID:**
   The `allowed_origins` in the manifest must match your actual extension ID

4. **Check browser console:**
   Open the extension's service worker (from `chrome://extensions`) and check for errors

### Vault file permissions

The vault file should only be readable by your user:
- **Linux/macOS:** `chmod 600 ~/.config/zenith-passkeys/vault.enc`
- **Windows:** File permissions are set automatically

### Browser-only (fallback) mode

If the native host isn't available, the extension runs in **fallback mode**:
- Uses PBKDF2 instead of Argon2id for key derivation
- Stores credentials in `chrome.storage.local`
- Vaults created in fallback mode are **not compatible** with the CLI vault format
- To migrate: export from fallback mode, then import into the CLI vault

### Google Drive backup

To use Google Drive backup:

```bash
pip install -e ./cli[gdrive]
zenith-passkeys backup push --provider gdrive
```

On first use, a browser window will open for Google OAuth authentication. The token is stored locally.

> ℹ️ The backup file uploaded to Google Drive is the same encrypted `vault.enc` file. Google cannot decrypt it.
