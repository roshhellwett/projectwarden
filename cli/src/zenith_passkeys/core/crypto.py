import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

MAGIC = b"ZNTH"
HEADER_SIZE_V1 = 166
HEADER_SIZE_V2 = 182
DEFAULT_KDF_ITERATIONS = 3
DEFAULT_KDF_MEMORY = 65536
DEFAULT_KDF_LANES = 4

@dataclass
class VaultHeader:
    version: int
    pw_salt: bytes
    rec_salt: bytes
    kdf_iterations: int
    kdf_memory: int
    kdf_lanes: int
    pw_wrapped_nonce: bytes
    pw_wrapped_mek: bytes
    rec_wrapped_nonce: bytes
    rec_wrapped_mek: bytes
    payload_nonce: bytes

    def size(self) -> int:
        return HEADER_SIZE_V1 if self.version == 1 else HEADER_SIZE_V2

    def aad(self) -> bytes:
        return (
            MAGIC
            + struct.pack("<H", self.version)
            + self.pw_salt
            + (self.pw_salt if self.version == 1 else self.rec_salt)
            + struct.pack("<III", self.kdf_iterations, self.kdf_memory, self.kdf_lanes)
        )

    def to_bytes(self) -> bytes:
        if self.version == 1:
            return (
                MAGIC
                + struct.pack("<H", self.version)
                + self.pw_salt
                + struct.pack("<III", self.kdf_iterations, self.kdf_memory, self.kdf_lanes)
                + self.pw_wrapped_nonce
                + self.pw_wrapped_mek
                + self.rec_wrapped_nonce
                + self.rec_wrapped_mek
                + self.payload_nonce
            )
        return (
            MAGIC
            + struct.pack("<H", self.version)
            + self.pw_salt
            + self.rec_salt
            + struct.pack("<III", self.kdf_iterations, self.kdf_memory, self.kdf_lanes)
            + self.pw_wrapped_nonce
            + self.pw_wrapped_mek
            + self.rec_wrapped_nonce
            + self.rec_wrapped_mek
            + self.payload_nonce
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "VaultHeader":
        if len(data) < 6:
            raise ValueError(f"Header too short: {len(data)}")
        if data[:4] != MAGIC:
            raise ValueError(f"Invalid magic bytes: {data[:4]!r}")
        version = struct.unpack("<H", data[4:6])[0]
        
        if version == 1:
            if len(data) < HEADER_SIZE_V1:
                raise ValueError("V1 header too short")
            pw_salt = data[6:22]
            rec_salt = pw_salt
            iterations, memory, lanes = struct.unpack("<III", data[22:34])
            offset = 34
        elif version >= 2:
            if len(data) < HEADER_SIZE_V2:
                raise ValueError("V2 header too short")
            pw_salt = data[6:22]
            rec_salt = data[22:38]
            iterations, memory, lanes = struct.unpack("<III", data[38:50])
            offset = 50
        else:
            raise ValueError(f"Unsupported vault version: {version}")

        if not (1 <= iterations <= 10000):
            raise ValueError(f"Invalid KDF iterations (DoS protection): {iterations}")
        if not (1024 <= memory <= 1024 * 1024 * 2):
            raise ValueError(f"Invalid KDF memory (DoS protection): {memory}")
        if not (1 <= lanes <= 128):
            raise ValueError(f"Invalid KDF lanes (DoS protection): {lanes}")
            
        pw_wrapped_nonce = data[offset:offset+12]
        pw_wrapped_mek = data[offset+12:offset+60]
        rec_wrapped_nonce = data[offset+60:offset+72]
        rec_wrapped_mek = data[offset+72:offset+120]
        payload_nonce = data[offset+120:offset+132]
        return cls(
            version=version, pw_salt=pw_salt, rec_salt=rec_salt,
            kdf_iterations=iterations, kdf_memory=memory, kdf_lanes=lanes,
            pw_wrapped_nonce=pw_wrapped_nonce, pw_wrapped_mek=pw_wrapped_mek,
            rec_wrapped_nonce=rec_wrapped_nonce, rec_wrapped_mek=rec_wrapped_mek,
            payload_nonce=payload_nonce,
        )

def derive_key(password: bytes, salt: bytes, iterations: int, memory: int, lanes: int) -> bytes:
    kdf = Argon2id(salt=salt, length=32, iterations=iterations, memory_cost=memory, lanes=lanes)
    return kdf.derive(password)

def encrypt_aes_gcm(plaintext: bytes, key: bytes, nonce: bytes, aad: bytes | None = None) -> bytes:
    return AESGCM(key).encrypt(nonce, plaintext, aad)

def decrypt_aes_gcm(ciphertext: bytes, key: bytes, nonce: bytes, aad: bytes | None = None) -> bytes:
    return AESGCM(key).decrypt(nonce, ciphertext, aad)
