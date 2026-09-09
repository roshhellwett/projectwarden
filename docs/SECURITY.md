# Security Policy

## Encryption Architecture

### Key Hierarchy

```
Master Password ─→ Argon2id KDF ─→ Wrapping Key ─→ AES-256-GCM wraps MEK
Recovery Key ───→ Argon2id KDF ─→ Wrapping Key ─→ AES-256-GCM wraps MEK (independently)
                                                         │
                                                    MEK (32 bytes)
                                                         │
                                              AES-256-GCM encrypts payload
                                                         │
                                               credentials + settings
```

- **MEK (Master Encryption Key):** 32 random bytes, unique per vault, never stored in plaintext
- **KDF parameters:** Argon2id with 3 iterations, 64MB memory, 4 lanes
- **Payload encryption:** AES-256-GCM with random 12-byte nonce
- **Recovery key:** 160-bit random value, displayed as 32 Base32 characters

### Vault File Format (V2)

```
ZNTH (4 bytes magic)
Version (2 bytes, little-endian)
PW Salt (16 bytes)
Recovery Salt (16 bytes)
KDF Iterations (4 bytes)
KDF Memory (4 bytes)
KDF Lanes (4 bytes)
PW Wrapped Nonce (12 bytes)
PW Wrapped MEK (48 bytes = 32 + 16 GCM tag)
Recovery Wrapped Nonce (12 bytes)
Recovery Wrapped MEK (48 bytes)
Payload Nonce (12 bytes)
─── Header ends (182 bytes) ───
Encrypted Payload (variable length, AES-256-GCM ciphertext)
```

### Additional Authenticated Data (AAD)

V2 vaults include AAD in all AES-GCM operations. The AAD is constructed from the header fields (magic, version, salts, KDF parameters), ensuring that tampering with the header is detected.

## Threat Model

### Local attacker with file access
- The vault file is encrypted with Argon2id + AES-256-GCM
- Without the master password or recovery key, the vault cannot be decrypted
- Argon2id parameters (64MB memory) resist GPU/ASIC-based brute force

### Cloud backup compromise
- The encrypted vault file is uploaded verbatim to cloud storage
- Cloud providers cannot decrypt it — they only see opaque encrypted data

### Browser compromise (XSS)
- WebAuthn private keys are decrypted only in the **native host process** (separate OS process)
- A page-level XSS attack cannot access keys directly
- The content script in the `MAIN` world only forwards serialized requests
- The `ISOLATED` world content script bridges to the extension's background service worker

### Fallback mode considerations
- In browser-only (fallback) mode, credentials are stored in `chrome.storage.local`
- Encryption uses PBKDF2-SHA256 (not Argon2id) with 600,000 iterations
- Fallback mode produces spec-conformant WebAuthn structures (CBOR attestation objects, COSE keys, DER signatures)
- Keys are held in memory within the browser's JavaScript runtime
- **Fallback mode is less secure** than native host mode — use it only when the CLI is not available

## Private Key Handling

- Private keys are stored AES-256-GCM encrypted in the vault file
- Decrypted only in-memory during WebAuthn ceremonies
- Byte arrays are zero-filled after use where possible
- Never logged, printed, or transmitted over the network

## Key Rotation

### Changing Your Password
```bash
zenith-passkeys change-password
```

This re-wraps the MEK with a new password-derived key. The MEK itself does not change, so all existing credentials remain valid — and **the recovery key keeps working** (both wrapping slots stay valid).

### Recovery Key

The recovery key is generated once at vault creation and survives password changes and vault recovery. If you suspect it's compromised:
1. Export your credentials: `zenith-passkeys export --out backup.enc --password`
2. Delete the vault file
3. Create a new vault: `zenith-passkeys init`
4. Import your credentials: `zenith-passkeys import backup.enc`

## Support

Something broke? Every failure shows a short error code — copy it and email
**zenithprojects@icloud.com**.

## Reporting Vulnerabilities

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead:
1. Email the maintainers directly (see the project's GitHub profile for contact info)
2. Include a clear description of the vulnerability and steps to reproduce
3. Allow reasonable time for a fix before public disclosure

We take all security reports seriously and will respond within 48 hours.
