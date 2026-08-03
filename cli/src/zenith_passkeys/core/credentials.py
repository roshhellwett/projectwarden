from .schema import VaultPayload, Credential
from datetime import datetime, timezone

def add_credential(payload: VaultPayload, cred: Credential) -> VaultPayload:
    # Remove existing credential with same rp_id and username to prevent duplicates
    payload.credentials = [
        c for c in payload.credentials 
        if not (c.rp_id == cred.rp_id and c.username == cred.username)
    ]
    if not cred.created_at:
        cred.created_at = datetime.now(timezone.utc).isoformat()
    payload.credentials.append(cred)
    return payload

def find_credentials(payload: VaultPayload, rp_id: str, allow_list: list[str] | None = None) -> list[Credential]:
    results = [c for c in payload.credentials if c.rp_id == rp_id]
    if allow_list is not None:
        results = [c for c in results if c.credential_id in allow_list]
    return results

def update_counter(payload: VaultPayload, credential_id: str, new_counter: int) -> VaultPayload:
    for cred in payload.credentials:
        if cred.credential_id == credential_id:
            cred.counter = new_counter
            cred.last_used_at = datetime.now(timezone.utc).isoformat()
            return payload
    raise ValueError(f"Credential {credential_id} not found")

def delete_credential(payload: VaultPayload, credential_id: str) -> VaultPayload:
    original_len = len(payload.credentials)
    payload.credentials = [c for c in payload.credentials if c.credential_id != credential_id]
    if len(payload.credentials) == original_len:
        raise ValueError(f"Credential {credential_id} not found")
    return payload
