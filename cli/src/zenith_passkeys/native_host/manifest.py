import json
import os
import re
import shutil
import sys
from pathlib import Path

# ──────────────────────────────────────────────────────────────────
# EXTENSION_ID: the Chrome/Edge extension ID allowed to talk to the
# native host.
# - EXTENSION_ID_WEBSTORE: Permanent ID assigned by the Chrome Web Store.
# - EXTENSION_ID_DEV: Local unpacked/developer mode extension ID.
# Both are allowed by default so the extension connects out of the box
# in both development and production.
# ──────────────────────────────────────────────────────────────────
EXTENSION_ID_WEBSTORE = "chrome-extension://doeecfkeppbpminhkcfjnbjmmdpkdkad/"
EXTENSION_ID_DEV = "chrome-extension://obmfjdinhjnajapckdjignghpjhalm/"
EXTENSION_ID_DEFAULT = EXTENSION_ID_WEBSTORE
EXTENSION_ID_FIREFOX = "zenith-passkeys@zenith.dev"

EXT_ID_RE = re.compile(r"^[a-p]{32}$")


def get_extension_id_path() -> Path:
    return Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "zenith-passkeys" / "native-manifests" / "extension_id.txt"


def load_extension_id() -> str:
    """Saved --extension-id wins; else the hardcoded default."""
    id_path = get_extension_id_path()
    if id_path.exists():
        saved = id_path.read_text().strip()
        if saved and saved not in ("chrome-extension://",):
            return saved if saved.startswith("chrome-extension://") else f"chrome-extension://{saved}/"
    return EXTENSION_ID_DEFAULT


def save_extension_id(ext_id: str) -> None:
    id_path = get_extension_id_path()
    id_path.parent.mkdir(parents=True, exist_ok=True)
    id_path.write_text(f"chrome-extension://{ext_id}/" if not ext_id.startswith("chrome-extension://") else ext_id)


def normalize_extension_id(ext_id: str) -> str:
    """Accept both raw 32-char IDs and chrome-extension:// URLs."""
    ext_id = ext_id.removeprefix("chrome-extension://")
    ext_id = ext_id.rstrip("/")
    if not EXT_ID_RE.match(ext_id):
        raise ValueError(
            f"Invalid extension ID: {ext_id!r}. Expected 32 characters a-p (the ID shown on chrome://extensions)."
        )
    return ext_id


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
    alt3 = Path(sys.executable).parent / "Scripts" / "zenith-passkeys-host.exe"
    if alt3.exists():
        return str(alt3)
    alt4 = Path(sys.executable).parent / "Scripts" / "zenith-passkeys-host"
    if alt4.exists():
        return str(alt4)
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
        origins = [EXTENSION_ID_WEBSTORE, EXTENSION_ID_DEV]
        custom_id = load_extension_id()
        if custom_id and custom_id not in origins:
            origins.append(custom_id)
        manifest = {
            "name": "com.zenith.passkeys",
            "description": "Zenith Passkeys native messaging host",
            "path": host_path,
            "type": "stdio",
            "allowed_origins": origins,
        }
    path.write_text(json.dumps(manifest, indent=2))


def get_chrome_manifest_dir() -> Path:
    if sys.platform == "linux":
        return Path.home() / ".config" / "google-chrome" / "NativeMessagingHosts"
    elif sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "Google" / "Chrome" / "NativeMessagingHosts"
    else:
        return Path(os.environ.get("LOCALAPPDATA", "")) / "zenith-passkeys" / "native-manifests" / "chrome"


def get_edge_manifest_dir() -> Path:
    if sys.platform == "linux":
        return Path.home() / ".config" / "microsoft-edge" / "NativeMessagingHosts"
    elif sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "Microsoft Edge" / "NativeMessagingHosts"
    else:
        return Path(os.environ.get("LOCALAPPDATA", "")) / "zenith-passkeys" / "native-manifests" / "edge"


def get_firefox_manifest_dir() -> Path:
    if sys.platform == "linux":
        return Path.home() / ".mozilla" / "native-messaging-hosts"
    elif sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "Mozilla" / "NativeMessagingHosts"
    else:
        return Path(os.environ.get("LOCALAPPDATA", "")) / "zenith-passkeys" / "native-manifests" / "firefox"


def register_native_host(extension_id: str | None = None) -> list[str]:
    """Write manifests + registry keys. Returns list of errors (empty = success)."""
    if extension_id:
        save_extension_id(normalize_extension_id(extension_id))

    host_path = get_host_path()
    manifest_name = "com.zenith.passkeys.json"
    errors: list[str] = []

    chrome_dir = get_chrome_manifest_dir()
    write_manifest(chrome_dir / manifest_name, host_path, is_firefox=False)
    edge_dir = get_edge_manifest_dir()
    write_manifest(edge_dir / manifest_name, host_path, is_firefox=False)
    firefox_dir = get_firefox_manifest_dir()
    write_manifest(firefox_dir / manifest_name, host_path, is_firefox=True)

    if sys.platform == "win32":
        errors.extend(_register_windows(chrome_dir, edge_dir, firefox_dir))

    if not Path(host_path).exists() and not shutil.which(host_path):
        errors.append(f"Host executable not found: {host_path}. Reinstall with: pip install -e ./cli")

    return errors


def _register_windows(chrome_dir: Path, edge_dir: Path, firefox_dir: Path) -> list[str]:
    errors: list[str] = []
    errors.extend(_winreg_key("Software\\Google\\Chrome\\NativeMessagingHosts\\com.zenith.passkeys",
                              str(chrome_dir / "com.zenith.passkeys.json")))
    errors.extend(_winreg_key("Software\\Microsoft\\Edge\\NativeMessagingHosts\\com.zenith.passkeys",
                              str(edge_dir / "com.zenith.passkeys.json")))
    errors.extend(_winreg_key("Software\\Mozilla\\NativeMessagingHosts\\com.zenith.passkeys",
                              str(firefox_dir / "com.zenith.passkeys.json")))
    return errors


def _winreg_key(key_path: str, value: str) -> list[str]:
    import winreg
    try:
        key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path)
        winreg.SetValueEx(key, "", 0, winreg.REG_SZ, value)
        winreg.CloseKey(key)
        return []
    except OSError as e:
        return [f"Registry write failed ({key_path}): {e}"]
