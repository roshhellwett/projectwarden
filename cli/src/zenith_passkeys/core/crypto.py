import os
import struct
from dataclasses import dataclass
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"ZNTH"
HEADER_SIZE = 166
DEFAULT_KDF_ITERATIONS = 3
DEFAULT_KDF_MEMORY = 65536
DEFAULT_KDF_LANES = 4

@dataclass
class VaultHeader:
    version: int
    kdf_salt: bytes
    kdf_iterations: int
    kdf_memory: int
    kdf_lanes: int
    pw_wrapped_nonce: bytes
    pw_wrapped_mek: bytes
    rec_wrapped_nonce: bytes
    rec_wrapped_mek: bytes
    payload_nonce: bytes

    def to_bytes(self) -> bytes:
        return (
            MAGIC
            + struct.pack("<H", self.version)
            + self.kdf_salt
            + struct.pack("<III", self.kdf_iterations, self.kdf_memory, self.kdf_lanes)
            + self.pw_wrapped_nonce
            + self.pw_wrapped_mek
            + self.rec_wrapped_nonce
            + self.rec_wrapped_mek
            + self.payload_nonce
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "VaultHeader":
        if len(data) < HEADER_SIZE:
            raise ValueError(f"Header too short: {len(data)} < {HEADER_SIZE}")
        if data[:4] != MAGIC:
            raise ValueError(f"Invalid magic bytes: {data[:4]!r}")
        version = struct.unpack("<H", data[4:6])[0]
        kdf_salt = data[6:22]
        iterations, memory, lanes = struct.unpack("<III", data[22:34])
        pw_wrapped_nonce = data[34:46]
        pw_wrapped_mek = data[46:94]
        rec_wrapped_nonce = data[94:106]
        rec_wrapped_mek = data[106:154]
        payload_nonce = data[154:166]
        return cls(
            version=version, kdf_salt=kdf_salt,
            kdf_iterations=iterations, kdf_memory=memory, kdf_lanes=lanes,
            pw_wrapped_nonce=pw_wrapped_nonce, pw_wrapped_mek=pw_wrapped_mek,
            rec_wrapped_nonce=rec_wrapped_nonce, rec_wrapped_mek=rec_wrapped_mek,
            payload_nonce=payload_nonce,
        )

def derive_key(password: bytes, salt: bytes, iterations: int, memory: int, lanes: int) -> bytes:
    kdf = Argon2id(salt=salt, length=32, iterations=iterations, memory_cost=memory, lanes=lanes)
    return kdf.derive(password)

def encrypt_aes_gcm(plaintext: bytes, key: bytes, nonce: bytes) -> bytes:
    return AESGCM(key).encrypt(nonce, plaintext, None)

def decrypt_aes_gcm(ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:
    return AESGCM(key).decrypt(nonce, ciphertext, None)
