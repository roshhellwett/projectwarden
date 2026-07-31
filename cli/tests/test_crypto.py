import os
import pytest
from zenith_passkeys.core.crypto import (
    VaultHeader, HEADER_SIZE_V1, HEADER_SIZE_V2, MAGIC,
    derive_key, encrypt_aes_gcm, decrypt_aes_gcm,
    DEFAULT_KDF_ITERATIONS, DEFAULT_KDF_MEMORY, DEFAULT_KDF_LANES,
)
from cryptography.exceptions import InvalidTag

def test_vault_header_roundtrip():
    header = VaultHeader(
        version=2,
        pw_salt=os.urandom(16),
        rec_salt=os.urandom(16),
        kdf_iterations=3,
        kdf_memory=65536,
        kdf_lanes=4,
        pw_wrapped_nonce=os.urandom(12),
        pw_wrapped_mek=os.urandom(48),
        rec_wrapped_nonce=os.urandom(12),
        rec_wrapped_mek=os.urandom(48),
        payload_nonce=os.urandom(12),
    )
    data = header.to_bytes()
    assert len(data) == HEADER_SIZE_V2
    header2 = VaultHeader.from_bytes(data)
    assert header2.version == header.version
    assert header2.pw_salt == header.pw_salt and header2.rec_salt == header.rec_salt
    assert header2.kdf_iterations == header.kdf_iterations
    assert header2.kdf_memory == header.kdf_memory
    assert header2.kdf_lanes == header.kdf_lanes
    assert header2.pw_wrapped_nonce == header.pw_wrapped_nonce
    assert header2.pw_wrapped_mek == header.pw_wrapped_mek
    assert header2.rec_wrapped_nonce == header.rec_wrapped_nonce
    assert header2.rec_wrapped_mek == header.rec_wrapped_mek
    assert header2.payload_nonce == header.payload_nonce

def test_header_invalid_magic():
    data = b"AAAA" + b"\x00" * (HEADER_SIZE_V1 - 4)
    with pytest.raises(ValueError, match="Invalid magic bytes"):
        VaultHeader.from_bytes(data)

def test_header_too_short():
    with pytest.raises(ValueError, match="V1 header too short"):
        VaultHeader.from_bytes(b"ZNTH" + b"\x01\x00" + b"\x00" * 10)

def test_derive_key_returns_32_bytes():
    key = derive_key(b"test", os.urandom(16), 1, 1024, 1)
    assert len(key) == 32

def test_encrypt_decrypt_roundtrip():
    key = os.urandom(32)
    nonce = os.urandom(12)
    plaintext = b"hello world"
    ct = encrypt_aes_gcm(plaintext, key, nonce)
    assert len(ct) == len(plaintext) + 16
    decrypted = decrypt_aes_gcm(ct, key, nonce)
    assert decrypted == plaintext

def test_decrypt_wrong_key():
    key = os.urandom(32)
    wrong_key = os.urandom(32)
    nonce = os.urandom(12)
    ct = encrypt_aes_gcm(b"test", key, nonce)
    with pytest.raises(InvalidTag):
        decrypt_aes_gcm(ct, wrong_key, nonce)

def test_decrypt_wrong_nonce():
    key = os.urandom(32)
    nonce = os.urandom(12)
    wrong_nonce = os.urandom(12)
    ct = encrypt_aes_gcm(b"test", key, nonce)
    with pytest.raises(InvalidTag):
        decrypt_aes_gcm(ct, key, wrong_nonce)

def test_derive_key_deterministic():
    password = b"test_password"
    salt = os.urandom(16)
    k1 = derive_key(password, salt, DEFAULT_KDF_ITERATIONS, DEFAULT_KDF_MEMORY, DEFAULT_KDF_LANES)
    k2 = derive_key(password, salt, DEFAULT_KDF_ITERATIONS, DEFAULT_KDF_MEMORY, DEFAULT_KDF_LANES)
    assert k1 == k2

def test_derive_key_different_salt():
    password = b"test_password"
    salt1 = os.urandom(16)
    salt2 = os.urandom(16)
    k1 = derive_key(password, salt1, DEFAULT_KDF_ITERATIONS, DEFAULT_KDF_MEMORY, DEFAULT_KDF_LANES)
    k2 = derive_key(password, salt2, DEFAULT_KDF_ITERATIONS, DEFAULT_KDF_MEMORY, DEFAULT_KDF_LANES)
    assert k1 != k2
