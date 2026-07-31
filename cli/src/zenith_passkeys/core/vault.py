import os
from pathlib import Path
from filelock import FileLock
from .paths import get_vault_file, get_vault_lock
from .crypto import (
    VaultHeader, HEADER_SIZE, MAGIC,
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
        from .recovery import generate_recovery_key

        mek = os.urandom(32)
        kdf_salt = os.urandom(16)
        raw_recovery, display_recovery = generate_recovery_key()

        dk = derive_key(password.encode(), kdf_salt, DEFAULT_KDF_ITERATIONS, DEFAULT_KDF_MEMORY, DEFAULT_KDF_LANES)
        rk = derive_key(raw_recovery, kdf_salt, DEFAULT_KDF_ITERATIONS, DEFAULT_KDF_MEMORY, DEFAULT_KDF_LANES)

        pw_nonce = os.urandom(12)
        pw_wrapped = encrypt_aes_gcm(mek, dk, pw_nonce)
        rec_nonce = os.urandom(12)
        rec_wrapped = encrypt_aes_gcm(mek, rk, rec_nonce)

        payload = VaultPayload()
        payload_nonce = os.urandom(12)
        payload_ct = encrypt_aes_gcm(payload.to_json(), mek, payload_nonce)

        header = VaultHeader(
            version=1, kdf_salt=kdf_salt,
            kdf_iterations=DEFAULT_KDF_ITERATIONS,
            kdf_memory=DEFAULT_KDF_MEMORY,
            kdf_lanes=DEFAULT_KDF_LANES,
            pw_wrapped_nonce=pw_nonce, pw_wrapped_mek=pw_wrapped,
            rec_wrapped_nonce=rec_nonce, rec_wrapped_mek=rec_wrapped,
            payload_nonce=payload_nonce,
        )

        with self.lock:
            self.vault_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.vault_path.with_suffix(".tmp")
            tmp.write_bytes(header.to_bytes() + payload_ct)
            os.replace(tmp, self.vault_path)

        return display_recovery, mek

    def unlock(self, password: str) -> tuple[VaultPayload, bytes]:
        with self.lock:
            raw = self.vault_path.read_bytes()

        header = VaultHeader.from_bytes(raw)
        dk = derive_key(password.encode(), header.kdf_salt, header.kdf_iterations, header.kdf_memory, header.kdf_lanes)
        mek = decrypt_aes_gcm(header.pw_wrapped_mek, dk, header.pw_wrapped_nonce)
        payload_ct = raw[HEADER_SIZE:]
        payload_json = decrypt_aes_gcm(payload_ct, mek, header.payload_nonce)
        return VaultPayload.from_json(payload_json), mek

    def unlock_with_recovery(self, recovery_key_raw: bytes) -> tuple[VaultPayload, bytes]:
        with self.lock:
            raw = self.vault_path.read_bytes()

        header = VaultHeader.from_bytes(raw)
        rk = derive_key(recovery_key_raw, header.kdf_salt, header.kdf_iterations, header.kdf_memory, header.kdf_lanes)
        mek = decrypt_aes_gcm(header.rec_wrapped_mek, rk, header.rec_wrapped_nonce)
        payload_ct = raw[HEADER_SIZE:]
        payload_json = decrypt_aes_gcm(payload_ct, mek, header.payload_nonce)
        return VaultPayload.from_json(payload_json), mek

    def save(self, payload: VaultPayload, mek: bytes) -> None:
        with self.lock:
            raw = self.vault_path.read_bytes()
            header = VaultHeader.from_bytes(raw)
            new_nonce = os.urandom(12)
            new_ct = encrypt_aes_gcm(payload.to_json(), mek, new_nonce)
            header.payload_nonce = new_nonce
            tmp = self.vault_path.with_suffix(".tmp")
            tmp.write_bytes(header.to_bytes() + new_ct)
            os.replace(tmp, self.vault_path)

    def change_password(self, old_password: str, new_password: str) -> None:
        with self.lock:
            raw = self.vault_path.read_bytes()
            header = VaultHeader.from_bytes(raw)
            dk_old = derive_key(old_password.encode(), header.kdf_salt, header.kdf_iterations, header.kdf_memory, header.kdf_lanes)
            mek = decrypt_aes_gcm(header.pw_wrapped_mek, dk_old, header.pw_wrapped_nonce)
            dk_new = derive_key(new_password.encode(), header.kdf_salt, header.kdf_iterations, header.kdf_memory, header.kdf_lanes)
            new_nonce = os.urandom(12)
            new_wrapped = encrypt_aes_gcm(mek, dk_new, new_nonce)
            header.pw_wrapped_nonce = new_nonce
            header.pw_wrapped_mek = new_wrapped
            payload_ct = raw[HEADER_SIZE:]
            tmp = self.vault_path.with_suffix(".tmp")
            tmp.write_bytes(header.to_bytes() + payload_ct)
            os.replace(tmp, self.vault_path)
