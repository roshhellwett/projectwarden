import os
from pathlib import Path
from filelock import FileLock
from .paths import get_vault_file, get_vault_lock
from .crypto import (
    VaultHeader, MAGIC,
    DEFAULT_KDF_ITERATIONS, DEFAULT_KDF_MEMORY, DEFAULT_KDF_LANES,
    derive_key, encrypt_aes_gcm, decrypt_aes_gcm,
)
from .schema import VaultPayload

class VaultManager:
    def __init__(self, vault_path: Path | None = None):
        self.vault_path = vault_path or get_vault_file()
        self.lock = FileLock(str(get_vault_lock()), timeout=10)

    def exists(self) -> bool:
        return self.vault_path.exists()

    def create(self, password: str) -> tuple[str, bytes]:
        """Create a new vault. Returns (recovery_key_display, master_encryption_key)."""
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters")
        if self.exists():
            raise FileExistsError("Vault already exists")
        from .recovery import generate_recovery_key

        mek = os.urandom(32)
        pw_salt = os.urandom(16)
        rec_salt = os.urandom(16)
        raw_recovery, display_recovery = generate_recovery_key()

        dk = derive_key(password.encode(), pw_salt, DEFAULT_KDF_ITERATIONS, DEFAULT_KDF_MEMORY, DEFAULT_KDF_LANES)
        rk = derive_key(raw_recovery, rec_salt, DEFAULT_KDF_ITERATIONS, DEFAULT_KDF_MEMORY, DEFAULT_KDF_LANES)

        header_proto = VaultHeader(
            version=2, pw_salt=pw_salt, rec_salt=rec_salt,
            kdf_iterations=DEFAULT_KDF_ITERATIONS, kdf_memory=DEFAULT_KDF_MEMORY, kdf_lanes=DEFAULT_KDF_LANES,
            pw_wrapped_nonce=b"", pw_wrapped_mek=b"",
            rec_wrapped_nonce=b"", rec_wrapped_mek=b"",
            payload_nonce=b"",
        )
        aad = header_proto.aad()

        pw_nonce = os.urandom(12)
        pw_wrapped = encrypt_aes_gcm(mek, dk, pw_nonce, aad)
        rec_nonce = os.urandom(12)
        rec_wrapped = encrypt_aes_gcm(mek, rk, rec_nonce, aad)

        payload = VaultPayload()
        payload_nonce = os.urandom(12)
        payload_ct = encrypt_aes_gcm(payload.to_json(), mek, payload_nonce, aad)

        header = VaultHeader(
            version=2, pw_salt=pw_salt, rec_salt=rec_salt,
            kdf_iterations=DEFAULT_KDF_ITERATIONS,
            kdf_memory=DEFAULT_KDF_MEMORY,
            kdf_lanes=DEFAULT_KDF_LANES,
            pw_wrapped_nonce=pw_nonce, pw_wrapped_mek=pw_wrapped,
            rec_wrapped_nonce=rec_nonce, rec_wrapped_mek=rec_wrapped,
            payload_nonce=payload_nonce,
        )

        with self.lock:
            self.vault_path.parent.mkdir(parents=True, exist_ok=True)
            try:
                self.vault_path.parent.chmod(0o700)
            except Exception:
                pass
            tmp = self.vault_path.with_suffix(".tmp")
            fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(header.to_bytes() + payload_ct)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.vault_path)

        return display_recovery, mek

    def unlock(self, password: str) -> tuple[VaultPayload, bytearray]:
        with self.lock:
            raw = self.vault_path.read_bytes()

        header = VaultHeader.from_bytes(raw)
        dk = derive_key(password.encode(), header.pw_salt, header.kdf_iterations, header.kdf_memory, header.kdf_lanes)
        aad = header.aad() if header.version >= 2 else None
        mek_bytes = decrypt_aes_gcm(header.pw_wrapped_mek, dk, header.pw_wrapped_nonce, aad)
        mek = bytearray(mek_bytes)
        payload_ct = raw[header.size():]
        payload_json = decrypt_aes_gcm(payload_ct, mek_bytes, header.payload_nonce, aad)
        return VaultPayload.from_json(payload_json), mek

    def unlock_with_recovery(self, recovery_key_raw: bytes) -> tuple[VaultPayload, bytearray]:
        with self.lock:
            raw = self.vault_path.read_bytes()

        header = VaultHeader.from_bytes(raw)
        rk = derive_key(recovery_key_raw, header.rec_salt, header.kdf_iterations, header.kdf_memory, header.kdf_lanes)
        aad = header.aad() if header.version >= 2 else None
        mek_bytes = decrypt_aes_gcm(header.rec_wrapped_mek, rk, header.rec_wrapped_nonce, aad)
        mek = bytearray(mek_bytes)
        payload_ct = raw[header.size():]
        payload_json = decrypt_aes_gcm(payload_ct, mek_bytes, header.payload_nonce, aad)
        return VaultPayload.from_json(payload_json), mek

    def save(self, payload: VaultPayload, mek: bytes) -> None:
        with self.lock:
            raw = self.vault_path.read_bytes()
            header = VaultHeader.from_bytes(raw)
            aad = header.aad() if header.version >= 2 else None
            new_nonce = os.urandom(12)
            new_ct = encrypt_aes_gcm(payload.to_json(), mek, new_nonce, aad)
            header.payload_nonce = new_nonce
            tmp = self.vault_path.with_suffix(".tmp")
            fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(header.to_bytes() + new_ct)
                f.flush()
                os.fsync(f.fileno())
            os.replace(str(tmp), str(self.vault_path))

    def update(self, updater, mek: bytes) -> VaultPayload:
        with self.lock:
            if not self.vault_path.exists():
                raise FileNotFoundError("Vault file not found")
            raw = self.vault_path.read_bytes()
            header = VaultHeader.from_bytes(raw)
            aad = header.aad() if header.version >= 2 else None
            
            payload_ct = raw[header.size():]
            payload_json = decrypt_aes_gcm(payload_ct, mek, header.payload_nonce, aad)
            payload = VaultPayload.from_json(payload_json)
            
            payload = updater(payload)
            
            new_nonce = os.urandom(12)
            new_ct = encrypt_aes_gcm(payload.to_json(), mek, new_nonce, aad)
            header.payload_nonce = new_nonce
            
            tmp = self.vault_path.with_suffix(".tmp")
            fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(header.to_bytes() + new_ct)
                f.flush()
                os.fsync(f.fileno())
            os.replace(str(tmp), str(self.vault_path))
            return payload

    def change_password(self, old_password: str, new_password: str) -> None:
        with self.lock:
            raw = self.vault_path.read_bytes()
            header = VaultHeader.from_bytes(raw)
            aad = header.aad() if header.version >= 2 else None
            dk_old = derive_key(old_password.encode(), header.pw_salt, header.kdf_iterations, header.kdf_memory, header.kdf_lanes)
            mek = decrypt_aes_gcm(header.pw_wrapped_mek, dk_old, header.pw_wrapped_nonce, aad)
            
            # If V2, we can safely rotate the password salt!
            old_aad = aad
            if header.version >= 2:
                header.pw_salt = os.urandom(16)
                aad = header.aad()
                
            dk_new = derive_key(new_password.encode(), header.pw_salt, header.kdf_iterations, header.kdf_memory, header.kdf_lanes)
            new_nonce = os.urandom(12)
            new_wrapped = encrypt_aes_gcm(mek, dk_new, new_nonce, aad)
            header.pw_wrapped_nonce = new_nonce
            header.pw_wrapped_mek = new_wrapped
            
            # Re-wrap payload with new AAD if it changed
            if header.version >= 2:
                payload_ct = raw[header.size():]
                payload_json = decrypt_aes_gcm(payload_ct, mek, header.payload_nonce, old_aad)
                new_payload_nonce = os.urandom(12)
                payload_ct = encrypt_aes_gcm(payload_json, mek, new_payload_nonce, aad)
                header.payload_nonce = new_payload_nonce
            else:
                payload_ct = raw[header.size():]
            tmp = self.vault_path.with_suffix(".tmp")
            fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(header.to_bytes() + payload_ct)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.vault_path)
