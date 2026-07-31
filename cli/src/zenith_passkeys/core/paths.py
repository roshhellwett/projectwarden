from pathlib import Path
from platformdirs import user_config_dir

def get_vault_dir() -> Path:
    d = Path(user_config_dir("zenith-passkeys", ensure_exists=True))
    return d

def get_vault_file() -> Path:
    return get_vault_dir() / "vault.enc"

def get_vault_lock() -> Path:
    return get_vault_dir() / "vault.enc.lock"

def get_config_file() -> Path:
    return get_vault_dir() / "config.toml"
