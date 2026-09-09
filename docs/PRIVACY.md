# Privacy Policy for Zenith Passkeys

**Last Updated:** September 2026  
**Publisher:** Zenith Open Source Projects  
**Contact:** zenithprojects@icloud.com  
**Repository:** https://github.com/roshhellwett/projectwarden  

---

## 1. Overview & Core Principle

**Zenith Passkeys** is a local-first, air-gapped WebAuthn & FIDO2 passkey manager. 

Our core architectural principle is **Zero Cloud, Zero Telemetry, and Zero Data Collection**. Your cryptographic keys, credentials, and personal data belong to you and never leave your local device.

---

## 2. Data Collection & Transmission

- **Zero Data Collection:** Zenith Passkeys does **not** collect, harvest, store, or transmit any personally identifiable information (PII), browsing history, website activity, or hardware identifiers.
- **Zero External Network Requests:** The browser extension and the local CLI daemon make **zero external network requests**. There are no cloud sync servers, third-party analytics, error-reporting beacons, or telemetry services.
- **Zero Third-Party Sharing:** We do not share, sell, or monetize user data under any circumstances.

---

## 3. Local Data Storage & Cryptographic Protection

- **Encrypted Local Vault:** All passkeys, resident credentials, relying party IDs (domains), and user metadata are stored strictly on your local computer inside an encrypted vault (`vault.enc`).
- **Cryptographic Standards:** Local vault encryption uses **AES-256-GCM** (Authenticated Encryption with Associated Data) with cryptographic keys derived via **Argon2id** (3 iterations, 64 MB memory, 4 lanes).
- **Zero-Knowledge Emergency Recovery:** Emergency recovery keys are used to re-wrap the vault Master Encryption Key in memory and are never persisted in plaintext on disk or in the browser.

---

## 4. Browser Permissions & Purpose

The Zenith Passkeys Chrome extension requests only the minimum permissions necessary to function as a FIDO2 authenticator:

- **`nativeMessaging`**: Used exclusively to communicate via standard local inter-process communication (IPC) with the background `zenith-passkeys-host` process running on your machine.
- **`storage`**: Used to save local extension interface preferences (such as auto-lock timeout duration) in the browser's local sandbox.
- **`activeTab`**: Used to determine the active website's origin when a WebAuthn ceremony is triggered, ensuring passkeys are only used on their authentic domains.
- **Host Permissions (`https://*/*`)**: Used solely to inject the WebAuthn API polyfill script that intercepts `navigator.credentials.create()` and `navigator.credentials.get()` to enable passkey registration and sign-in.

---

## 5. User Rights & Data Control

- You have full ownership of your data.
- You can export, backup, or delete your credentials at any time directly through the Zenith Passkeys dashboard or the CLI.
- Removing the extension and deleting your local vault file permanently removes all associated data from your system.

---

## 6. Open Source Transparency

Zenith Passkeys is 100% open-source software licensed under the MIT License. Anyone can audit our source code, cryptographic algorithms, and build artifacts at:  
https://github.com/roshhellwett/projectwarden

---

## 7. Contact & Security Disclosures

If you have any questions, feedback, or security disclosures regarding this Privacy Policy, please contact:  
**Email:** zenithprojects@icloud.com
