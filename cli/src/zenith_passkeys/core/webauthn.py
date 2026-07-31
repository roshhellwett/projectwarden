import os
import json
import hashlib
import struct
import base64
import cbor2
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from .schema import Credential

AAGUID = b"\x00" * 16

def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def base64url_decode(s: str) -> bytes:
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)

def generate_credential_keypair() -> tuple[bytes, bytes, bytes]:
    private_key = ec.generate_private_key(ec.SECP256R1())
    private_bytes = private_key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pub_numbers = private_key.public_key().public_numbers()
    x = pub_numbers.x.to_bytes(32, "big")
    y = pub_numbers.y.to_bytes(32, "big")
    cose_key = {
        1: 2,
        3: -7,
        -1: 1,
        -2: x,
        -3: y,
    }
    cose_bytes = cbor2.dumps(cose_key)
    credential_id = os.urandom(32)
    return private_bytes, cose_bytes, credential_id

def build_authenticator_data(rp_id: str, flags: int, counter: int,
                              attested_cred_data: bytes | None = None) -> bytes:
    rp_id_hash = hashlib.sha256(rp_id.encode("utf-8")).digest()
    auth_data = rp_id_hash + struct.pack("B", flags) + struct.pack(">I", counter)
    if attested_cred_data:
        auth_data += attested_cred_data
    return auth_data

def build_attested_credential_data(credential_id: bytes, cose_public_key: bytes) -> bytes:
    return AAGUID + struct.pack(">H", len(credential_id)) + credential_id + cose_public_key

def create_credential_response(rp_id: str, origin: str, challenge_b64url: str,
                                 user_handle: bytes, username: str) -> tuple[dict, Credential]:
    private_bytes, cose_bytes, credential_id = generate_credential_keypair()
    attested = build_attested_credential_data(credential_id, cose_bytes)
    auth_data = build_authenticator_data(rp_id, 0x45, 0, attested)
    attestation_object = cbor2.dumps({
        "fmt": "none",
        "attStmt": {},
        "authData": auth_data,
    })
    client_data = {
        "type": "webauthn.create",
        "challenge": challenge_b64url,
        "origin": origin,
        "crossOrigin": False,
    }
    client_data_json = json.dumps(client_data, separators=(",", ":")).encode("utf-8")
    response = {
        "id": base64url_encode(credential_id),
        "rawId": base64url_encode(credential_id),
        "type": "public-key",
        "response": {
            "attestationObject": base64url_encode(attestation_object),
            "clientDataJSON": base64url_encode(client_data_json),
        },
        "authenticatorAttachment": "platform",
    }
    cred = Credential(
        rp_id=rp_id,
        credential_id=base64url_encode(credential_id),
        private_key=base64url_encode(private_bytes),
        public_key=base64url_encode(cose_bytes),
        user_handle=base64url_encode(user_handle),
        username=username,
        counter=0,
        algorithm=-7,
    )
    return response, cred

def get_assertion_response(credential: Credential, rp_id: str, origin: str,
                              challenge_b64url: str) -> tuple[dict, int]:
    private_key_bytes = base64url_decode(credential.private_key)
    private_key = serialization.load_der_private_key(private_key_bytes, password=None)
    new_counter = credential.counter + 1
    auth_data = build_authenticator_data(rp_id, 0x05, new_counter)
    client_data = {
        "type": "webauthn.get",
        "challenge": challenge_b64url,
        "origin": origin,
        "crossOrigin": False,
    }
    client_data_json = json.dumps(client_data, separators=(",", ":")).encode("utf-8")
    client_data_hash = hashlib.sha256(client_data_json).digest()
    signed_data = auth_data + client_data_hash
    signature_der = private_key.sign(signed_data, ec.ECDSA(hashes.SHA256()))
    response = {
        "id": credential.credential_id,
        "rawId": credential.credential_id,
        "type": "public-key",
        "response": {
            "authenticatorData": base64url_encode(auth_data),
            "clientDataJSON": base64url_encode(client_data_json),
            "signature": base64url_encode(signature_der),
            "userHandle": credential.user_handle,
        },
        "authenticatorAttachment": "platform",
    }
    return response, new_counter
