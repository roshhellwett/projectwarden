from dataclasses import dataclass, field, asdict
from typing import Optional
import json

@dataclass
class Credential:
    rp_id: str
    credential_id: str
    private_key: str
    public_key: str
    user_handle: str
    username: str
    counter: int = 0
    created_at: str = ""
    last_used_at: Optional[str] = None
    algorithm: int = -7

@dataclass
class Settings:
    idle_timeout_minutes: int = 15
    backup_provider: Optional[str] = None  # "gdrive" | None
    use_keyring: bool = False

@dataclass
class VaultPayload:
    version: int = 1
    credentials: list[Credential] = field(default_factory=list)
    settings: Settings = field(default_factory=Settings)

    def to_json(self) -> bytes:
        d = asdict(self)
        return json.dumps(d, separators=(",", ":")).encode("utf-8")

    @classmethod
    def from_json(cls, data: bytes) -> "VaultPayload":
        d = json.loads(data.decode("utf-8"))
        creds = [Credential(**c) for c in d.get("credentials", [])]
        settings = Settings(**d.get("settings", {}))
        return cls(version=d.get("version", 1), credentials=creds, settings=settings)
