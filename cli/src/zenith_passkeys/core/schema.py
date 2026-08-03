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

    def validate(self):
        if not isinstance(self.idle_timeout_minutes, int) or getattr(self, 'idle_timeout_minutes', 0) < 1:
            raise ValueError("idle_timeout_minutes must be an integer >= 1")
        if self.backup_provider is not None and not isinstance(self.backup_provider, str):
            raise ValueError("backup_provider must be a string or None")
        if not isinstance(self.use_keyring, bool):
            raise ValueError("use_keyring must be a boolean")

@dataclass
class LogEntry:
    timestamp: float
    action: str
    status: str
    details: str

@dataclass
class VaultPayload:
    version: int = 1
    credentials: list[Credential] = field(default_factory=list)
    settings: Settings = field(default_factory=Settings)
    action_log: list[LogEntry] = field(default_factory=list)

    def to_json(self) -> bytes:
        d = asdict(self)
        return json.dumps(d, separators=(",", ":")).encode("utf-8")

    @classmethod
    def from_json(cls, data: bytes) -> "VaultPayload":
        d = json.loads(data.decode("utf-8"))
        creds = [Credential(**c) for c in d.get("credentials", [])]
        settings = Settings(**d.get("settings", {}))
        settings.validate()
        logs = [LogEntry(**l) for l in d.get("action_log", [])]
        return cls(version=d.get("version", 1), credentials=creds, settings=settings, action_log=logs)
