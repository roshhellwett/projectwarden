import os
from pathlib import Path

from platformdirs import user_config_dir


def get_vault_dir() -> Path:
    """Vault/config directory.

    ZENITH_HOME env var overrides the platform default (portable installs,
    testing, multi-vault setups). Otherwise platformdirs resolves it
    (%LOCALAPPDATA%\\zenith-passkeys\\zenith-passkeys on Windows).
    """
    override = os.environ.get("ZENITH_HOME")
    if override:
        d = Path(override)
    else:
        d = Path(user_config_dir("zenith-passkeys", ensure_exists=True))
    d.mkdir(parents=True, exist_ok=True)
    return d


def get_vault_file() -> Path:
    return get_vault_dir() / "vault.enc"


def get_vault_lock() -> Path:
    return get_vault_dir() / "vault.enc.lock"


def get_config_file() -> Path:
    return get_vault_dir() / "config.toml"
