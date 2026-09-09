import os
from pathlib import Path

from cryptography.exceptions import InvalidTag
from filelock import FileLock

from .crypto import (
    DEFAULT_KDF_ITERATIONS,
    DEFAULT_KDF_LANES,
    DEFAULT_KDF_MEMORY,
    VaultHeader,
    decrypt_aes_gcm,
    derive_key,
    encrypt_aes_gcm,
)
from .paths import get_vault_file, get_vault_lock
from .schema import VaultPayload


class VaultManager:
    def __init__(self, vault_path: Path | None = None):
        self.vault_path = vault_path or get_vault_file()
        self.lock = FileLock(str(get_vault_lock()), timeout=10)

    def exists(self) -> bool:
        return self.vault_path.exists()

    def _atomic_write(self, data: bytes) -> None:
        """Write vault bytes atomically: temp file + fsync + rename."""
        self.vault_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self.vault_path.parent.chmod(0o700)
        except Exception:  # noqa: BLE001, S110 - Windows chmod is best-effort
            pass
        tmp = self.vault_path.with_suffix(".tmp")
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(str(tmp), str(self.vault_path))

    def create(self, password: str) -> tuple[str, bytearray]:
        """Create a new vault. Returns (recovery_key_display, master_encryption_key)."""
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters")
        if self.exists():
            raise FileExistsError("Vault already exists")
        from .recovery import generate_recovery_key

        mek = bytearray(os.urandom(32))
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
        pw_wrapped = encrypt_aes_gcm(bytes(mek), dk, pw_nonce, aad)
        rec_nonce = os.urandom(12)
        rec_wrapped = encrypt_aes_gcm(bytes(mek), rk, rec_nonce, aad)

        payload = VaultPayload()
        payload_nonce = os.urandom(12)
        payload_ct = encrypt_aes_gcm(payload.to_json(), bytes(mek), payload_nonce, aad)

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
            self._atomic_write(header.to_bytes() + payload_ct)

        return display_recovery, mek

    def unlock(self, password: str) -> tuple[VaultPayload, bytearray]:
        with self.lock:
            raw = self.vault_path.read_bytes()

        header = VaultHeader.from_bytes(raw)
        dk = derive_key(password.encode(), header.pw_salt, header.kdf_iterations, header.kdf_memory, header.kdf_lanes)
        aad = header.aad() if header.version >= 2 else None

        try:
            mek_bytes = decrypt_aes_gcm(header.pw_wrapped_mek, dk, header.pw_wrapped_nonce, aad)
        except InvalidTag:
            raise ValueError("Invalid master password or corrupted vault") from None

        mek = bytearray(mek_bytes)
        payload_ct = raw[header.size():]
        try:
            payload_json = decrypt_aes_gcm(payload_ct, bytes(mek), header.payload_nonce, aad)
        except InvalidTag:
            raise ValueError("Vault payload is corrupted") from None
        return VaultPayload.from_json(payload_json), mek

    def unlock_with_recovery(self, recovery_key_raw: bytes) -> tuple[VaultPayload, bytearray]:
        with self.lock:
            raw = self.vault_path.read_bytes()

        header = VaultHeader.from_bytes(raw)
        rk = derive_key(recovery_key_raw, header.rec_salt, header.kdf_iterations, header.kdf_memory, header.kdf_lanes)
        aad = header.aad() if header.version >= 2 else None
        try:
            mek_bytes = decrypt_aes_gcm(header.rec_wrapped_mek, rk, header.rec_wrapped_nonce, aad)
        except InvalidTag:
            raise ValueError("Invalid recovery key or corrupted vault") from None
        mek = bytearray(mek_bytes)
        payload_ct = raw[header.size():]
        try:
            payload_json = decrypt_aes_gcm(payload_ct, bytes(mek), header.payload_nonce, aad)
        except InvalidTag:
            raise ValueError("Vault payload is corrupted") from None
        return VaultPayload.from_json(payload_json), mek

    def save(self, payload: VaultPayload, mek: bytes) -> None:
        with self.lock:
            raw = self.vault_path.read_bytes()
            header = VaultHeader.from_bytes(raw)
            aad = header.aad() if header.version >= 2 else None
            new_nonce = os.urandom(12)
            new_ct = encrypt_aes_gcm(payload.to_json(), bytes(mek), new_nonce, aad)
            header.payload_nonce = new_nonce
            self._atomic_write(header.to_bytes() + new_ct)

    def update(self, updater, mek: bytes) -> VaultPayload:
        with self.lock:
            if not self.vault_path.exists():
                raise FileNotFoundError("Vault file not found")
            raw = self.vault_path.read_bytes()
            header = VaultHeader.from_bytes(raw)
            aad = header.aad() if header.version >= 2 else None

            payload_ct = raw[header.size():]
            payload_json = decrypt_aes_gcm(payload_ct, bytes(mek), header.payload_nonce, aad)
            payload = VaultPayload.from_json(payload_json)

            payload = updater(payload)

            new_nonce = os.urandom(12)
            new_ct = encrypt_aes_gcm(payload.to_json(), bytes(mek), new_nonce, aad)
            header.payload_nonce = new_nonce

            self._atomic_write(header.to_bytes() + new_ct)
            return payload

    def change_password(self, old_password: str, new_password: str) -> None:
        """Re-wrap the MEK under a new master password.

        The salts (and therefore the AAD) are intentionally kept unchanged so
        the recovery-wrapped MEK remains valid: the recovery key keeps working
        after a password change. Rotating pw_salt here would silently destroy
        the recovery path (see audit F-001).
        """
        if len(new_password) < 8:
            raise ValueError("Password must be at least 8 characters")
        with self.lock:
            raw = self.vault_path.read_bytes()
            header = VaultHeader.from_bytes(raw)
            aad = header.aad() if header.version >= 2 else None
            dk_old = derive_key(old_password.encode(), header.pw_salt, header.kdf_iterations, header.kdf_memory, header.kdf_lanes)
            try:
                mek = decrypt_aes_gcm(header.pw_wrapped_mek, dk_old, header.pw_wrapped_nonce, aad)
            except InvalidTag:
                raise ValueError("Invalid master password or corrupted vault") from None

            dk_new = derive_key(new_password.encode(), header.pw_salt, header.kdf_iterations, header.kdf_memory, header.kdf_lanes)
            new_nonce = os.urandom(12)
            header.pw_wrapped_nonce = new_nonce
            header.pw_wrapped_mek = encrypt_aes_gcm(mek, dk_new, new_nonce, aad)

            # Payload ciphertext is untouched: same MEK, same AAD, same nonce.
            self._atomic_write(header.to_bytes() + raw[header.size():])

    def set_password_with_recovery(self, recovery_key_raw: bytes, new_password: str) -> bytearray:
        """Recover the vault with the recovery key and set a new master password.

        V2 vaults rotate BOTH salts and re-wrap both slots under the new AAD,
        so the same displayed recovery key stays usable afterwards.
        Returns the MEK (bytearray) so callers can keep the session unlocked.
        """
        if len(new_password) < 8:
            raise ValueError("Password must be at least 8 characters")
        with self.lock:
            raw = self.vault_path.read_bytes()
            header = VaultHeader.from_bytes(raw)
            params = (header.kdf_iterations, header.kdf_memory, header.kdf_lanes)

            rk_old = derive_key(recovery_key_raw, header.rec_salt, *params)
            old_aad = header.aad() if header.version >= 2 else None
            try:
                mek = decrypt_aes_gcm(header.rec_wrapped_mek, rk_old, header.rec_wrapped_nonce, old_aad)
            except InvalidTag:
                raise ValueError("Invalid recovery key or corrupted vault") from None

            if header.version >= 2:
                # Rotate both salts; the recovery key raw bytes are unchanged,
                # only its wrapping key is re-derived from the new rec_salt.
                header.pw_salt = os.urandom(16)
                header.rec_salt = os.urandom(16)
                new_aad = header.aad()

                payload_ct = raw[header.size():]
                payload_json = decrypt_aes_gcm(payload_ct, mek, header.payload_nonce, old_aad)

                dk_new = derive_key(new_password.encode(), header.pw_salt, *params)
                rk_new = derive_key(recovery_key_raw, header.rec_salt, *params)

                pw_nonce = os.urandom(12)
                header.pw_wrapped_nonce = pw_nonce
                header.pw_wrapped_mek = encrypt_aes_gcm(mek, dk_new, pw_nonce, new_aad)

                rec_nonce = os.urandom(12)
                header.rec_wrapped_nonce = rec_nonce
                header.rec_wrapped_mek = encrypt_aes_gcm(mek, rk_new, rec_nonce, new_aad)

                payload_nonce = os.urandom(12)
                header.payload_nonce = payload_nonce
                payload_ct = encrypt_aes_gcm(payload_json, mek, payload_nonce, new_aad)

                self._atomic_write(header.to_bytes() + payload_ct)
            else:
                # V1: single salt feeds both slots; rotate nothing, re-wrap the
                # password slot only so the recovery slot keeps its AAD.
                dk_new = derive_key(new_password.encode(), header.pw_salt, *params)
                new_nonce = os.urandom(12)
                header.pw_wrapped_nonce = new_nonce
                header.pw_wrapped_mek = encrypt_aes_gcm(mek, dk_new, new_nonce, None)
                self._atomic_write(header.to_bytes() + raw[header.size():])

        return bytearray(mek)

    def rotate_recovery_key(self, mek: bytearray | bytes) -> str:
        """Generate and set a new emergency recovery key for an unlocked vault.

        Preserves salts and AAD so the master password and payload are unaffected.
        Re-wraps the MEK under the newly generated recovery key in the recovery slot.
        Returns the formatted 32-character display key (XXXX-XXXX-...).
        """
        from .recovery import generate_recovery_key

        with self.lock:
            raw = self.vault_path.read_bytes()
            header = VaultHeader.from_bytes(raw)
            aad = header.aad() if header.version >= 2 else None

            raw_rec, display_rec = generate_recovery_key()
            rk = derive_key(
                raw_rec,
                header.rec_salt,
                header.kdf_iterations,
                header.kdf_memory,
                header.kdf_lanes,
            )
            new_nonce = os.urandom(12)
            header.rec_wrapped_nonce = new_nonce
            header.rec_wrapped_mek = encrypt_aes_gcm(bytes(mek), rk, new_nonce, aad)

            self._atomic_write(header.to_bytes() + raw[header.size():])
            return display_rec
