import pytest
from zenith_passkeys.core.webauthn import (
    base64url_encode, base64url_decode,
    generate_credential_keypair,
    build_authenticator_data, build_attested_credential_data,
    create_credential_response, get_assertion_response,
)
from zenith_passkeys.core.schema import Credential

def test_base64url_roundtrip():
    data = b"hello world\x00\xff\xfe"
    encoded = base64url_encode(data)
    decoded = base64url_decode(encoded)
    assert decoded == data

def test_generate_keypair():
    priv, cose, cred_id = generate_credential_keypair()
    assert len(priv) > 0
    assert len(cose) > 0
    assert len(cred_id) == 32

def test_build_authenticator_data():
    data = build_authenticator_data("example.com", 0x05, 1)
    assert len(data) == 37

def test_build_authenticator_data_with_attested():
    data = build_authenticator_data("example.com", 0x45, 0, b"\x00" * 50)
    assert len(data) == 37 + 50

def test_build_attested_credential_data():
    data = build_attested_credential_data(b"\x01" * 32, b"\x02" * 77)
    assert len(data) == 16 + 2 + 32 + 77

def test_create_credential_response():
    response, cred = create_credential_response(
        "example.com", "https://example.com", "challenge",
        b"\x00" * 16, "testuser",
    )
    assert response["type"] == "public-key"
    assert response["authenticatorAttachment"] == "platform"
    assert "attestationObject" in response["response"]
    assert cred.rp_id == "example.com"
    assert cred.username == "testuser"
    assert cred.counter == 0
    assert cred.algorithm == -7

def test_get_assertion_response():
    _, cred = create_credential_response(
        "example.com", "https://example.com", "challenge",
        b"\x00" * 16, "testuser",
    )
    response, new_counter = get_assertion_response(
        cred, "example.com", "https://example.com", "challenge2",
    )
    assert response["type"] == "public-key"
    assert "signature" in response["response"]
    assert new_counter == 1
