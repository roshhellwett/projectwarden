# Security Policy

## Encryption Architecture

- **Key hierarchy**: Master password → Argon2id KDF → wrapping key → AES-256-GCM wraps MEK
- **MEK**: 32 random bytes, unique per vault, never stored in plaintext
- **Payload**: AES-256-GCM encrypted with MEK
- **Recovery key**: 256-bit random key, wraps MEK independently

## Threat Model

- **Local attacker with file access**: Vault is encrypted with Argon2id + AES-256-GCM. Without the password or recovery key, the vault cannot be decrypted.
- **Cloud backup compromise**: The encrypted vault file is uploaded verbatim. Cloud providers cannot decrypt it.
- **Browser compromise**: WebAuthn private keys are decrypted in the native host process (or in-memory in fallback mode). A page-level XSS cannot access them.

## Private Key Handling

- Private keys are stored AES-256-GCM encrypted in the vault file
- Decrypted only in-memory during WebAuthn ceremonies
- Never logged, printed, or transmitted over the network

## Reporting Vulnerabilities

Open a GitHub issue for security concerns.
