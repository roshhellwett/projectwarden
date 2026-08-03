import json
import os
import shutil
import sys
from pathlib import Path

# ──────────────────────────────────────────────────────────────────
# EXTENSION_ID is the permanent ID of your published extension.
# When you publish to the Chrome Web Store, you will get a permanent
# ID. Hardcode it here so your end-users never have to configure it!
# ──────────────────────────────────────────────────────────────────
EXTENSION_ID = "chrome-extension://mdpajbajbaemmgajbdjdfiflhcngplpf/"
EXTENSION_ID_FIREFOX = "zenith-passkeys@zenith.dev"

def get_host_path() -> str:
    host = shutil.which("zenith-passkeys-host")
    if host:
        return host
    alt = Path(sys.executable).parent / "zenith-passkeys-host"
    if alt.exists():
        return str(alt)
    alt2 = Path(sys.executable).parent / "zenith-passkeys-host.exe"
    if alt2.exists():
        return str(alt2)
    return "zenith-passkeys-host"

def write_manifest(path: Path, host_path: str, is_firefox: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if is_firefox:
        manifest = {
            "name": "com.zenith.passkeys",
            "description": "Zenith Passkeys native messaging host",
            "path": host_path,
            "type": "stdio",
            "allowed_extensions": [EXTENSION_ID_FIREFOX],
        }
    else:
        manifest = {
            "name": "com.zenith.passkeys",
            "description": "Zenith Passkeys native messaging host",
            "path": host_path,
            "type": "stdio",
            "allowed_origins": [EXTENSION_ID],
        }
    path.write_text(json.dumps(manifest, indent=2))

def get_chrome_manifest_dir() -> Path:
    if sys.platform == "linux":
        return Path.home() / ".config" / "google-chrome" / "NativeMessagingHosts"
    elif sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "Google" / "Chrome" / "NativeMessagingHosts"
    else:
        return Path(os.environ.get("LOCALAPPDATA", "")) / "zenith-passkeys" / "native-manifests"

def get_edge_manifest_dir() -> Path:
    if sys.platform == "linux":
        return Path.home() / ".config" / "microsoft-edge" / "NativeMessagingHosts"
    elif sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "Microsoft Edge" / "NativeMessagingHosts"
    else:
        return Path(os.environ.get("LOCALAPPDATA", "")) / "zenith-passkeys" / "native-manifests"

def get_firefox_manifest_dir() -> Path:
    if sys.platform == "linux":
        return Path.home() / ".mozilla" / "native-messaging-hosts"
    elif sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "Mozilla" / "NativeMessagingHosts"
    else:
        return Path(os.environ.get("LOCALAPPDATA", "")) / "zenith-passkeys" / "native-manifests"

def register_native_host() -> None:
    host_path = get_host_path()
    manifest_name = "com.zenith.passkeys.json"

    chrome_dir = get_chrome_manifest_dir()
    write_manifest(chrome_dir / manifest_name, host_path, is_firefox=False)
    edge_dir = get_edge_manifest_dir()
    write_manifest(edge_dir / manifest_name, host_path, is_firefox=False)
    firefox_dir = get_firefox_manifest_dir()
    write_manifest(firefox_dir / manifest_name, host_path, is_firefox=True)

    if sys.platform == "win32":
        import winreg
        _register_windows(chrome_dir, edge_dir, firefox_dir)

def _register_windows(chrome_dir: Path, edge_dir: Path, firefox_dir: Path) -> None:
    _winreg_key("Software\\Google\\Chrome\\NativeMessagingHosts\\com.zenith.passkeys",
                str(chrome_dir / "com.zenith.passkeys.json"))
    _winreg_key("Software\\Microsoft\\Edge\\NativeMessagingHosts\\com.zenith.passkeys",
                str(edge_dir / "com.zenith.passkeys.json"))
    _winreg_key("Software\\Mozilla\\NativeMessagingHosts\\com.zenith.passkeys",
                str(firefox_dir / "com.zenith.passkeys.json"))

def _winreg_key(key_path: str, value: str) -> None:
    import winreg
    try:
        key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path)
        winreg.SetValueEx(key, "", 0, winreg.REG_SZ, value)
        winreg.CloseKey(key)
    except Exception:
        pass
