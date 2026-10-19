# Zenith Passkeys — Full Project Audit (2026-09-09)

Auditor: Hermes Agent, first-hand source review + live runtime probes. All 🔴/🟠 findings verified by execution, not just reading.
Working tree was clean at audit start. No files modified. Real vault at `%LOCALAPPDATA%\zenith-passkeys\` never touched (probes used temp dirs).

## Verdict: NO-SHIP (as public v1.0.0)

Crypto core is well-designed (Argon2id 64MB/t=3, AES-256-GCM with header AAD, MEK wrap hierarchy, atomic writes, KDF DoS caps, filelock, rpId↔origin validation). The failures are in the flows around it: a data-loss bug, broken distribution, a placebo lock, and a fallback mode that cannot work against real sites.

---

## 🔴 CRITICAL

### F-001 — change-password permanently destroys the recovery key
- **Evidence (live probe):** create vault → `change_password("old","new")` → new password unlocks OK → `unlock_with_recovery(key)` raises `InvalidTag`. `cli/src/zenith_passkeys/core/vault.py:158-193` rotates `pw_salt` (→ new AAD) and re-wraps `pw_wrapped_mek` + payload, but **never re-wraps `rec_wrapped_mek`** with the new AAD. `unlock_with_recovery` (vault.py:107-112) decrypts with current `header.aad()` → tag mismatch.
- Same bug class in the recover flow: `cli/src/zenith_passkeys/commands/init_cmd.py:44-66` (verified by probe 2: recovery key is single-use — after `init --recover` the same recovery key is dead).
- **Impact:** forget master password after any password change → vault unrecoverable → **total loss of all passkeys**. SECURITY.md's promise ("Recovery Key ... wraps the same MEK independently") silently broken.
- **Fix sketch:** re-encrypt `rec_wrapped_mek` under the new AAD in both `change_password` and the recover flow (optionally rotate `rec_salt` + re-derive rk too, keeping the same displayed key). Add regression tests: recovery works after change-password, and after recover.

### F-002 — Wrong password hits the fatal-error panel in every CLI command
- **Evidence (live):** `zenith-passkeys list` + wrong password → red "Fatal Error" panel with base64 code (`SW52YWxpZCBtYXN0ZXIgcGFzc3dvcmQ...`). Unit tests `test_unlock_wrong_password`, `test_change_password` FAIL. Repo's own `audit_test.py`: 3 failures incl. "Wrong password correctly rejected".
- **Root cause:** `vault.unlock` (vault.py:90-92,99) converts `InvalidTag` → `ValueError`, but 9 commands catch only `InvalidTag` (list_cmd.py:27, export_cmd.py:25, import_cmd.py:26, delete_cmd.py:24, config_cmd.py:22, change_password_cmd.py:19, audit_cmd.py:25, backup_cmd.py:26-28, init_cmd.py:36). Only `logs_cmd.py:39` catches `ValueError` (the lone correct one).
- **Fix sketch:** standardize: either re-raise `InvalidTag` from `vault.unlock` or catch `(InvalidTag, ValueError)` in all commands. Fix the 2 tests to match whichever contract is chosen.

## 🟠 HIGH

### F-003 — Google OAuth client_secret committed to a public repo
- `cli/src/zenith_passkeys/backup/gdrive.py:5-6` — `client_id` + `GOCSPX-…` secret hardcoded; repo pushes to github.com/roshhellwett/projectwarden. Installed-app secrets are low-sensitivity per Google, but anyone can now impersonate this app's consent screen. Rotate the secret; read from env/config instead.

### F-004 — Fallback (browser-only) mode produces non-conformant WebAuthn structures
- **Evidence (probe):** `fallback-vault.js:188` encodes `attestationObject` as **JSON bytes**; CBOR decode fails (WebAuthn requires CBOR) → every registration on a conformant RP fails. `fallback-vault.js:226` signs with WebCrypto ECDSA → **raw r||s**, WebAuthn requires ASN.1 DER (native host's `cryptography` path produces proper DER 0x30…). Assertions also rejected.
- Impact: fallback mode is presented as a working mode (banner, README, SETUP.md "migration" instructions) but cannot complete a single real ceremony. Fix: embed a tiny CBOR encoder + DER signature converter (the dead `extension/lib/cbor.js` hints this was planned), or remove fallback WebAuthn and keep fallback as view-only.

### F-005 — Popup "Recover Vault" is a dead end
- `extension/popup/popup.js:135-139` relabels the create form "Recover", but `doCreateVault()` sends `create_vault`; native host dispatch (`host.py:51-64`) has **no recover action** → user gets "Vault already exists" error. The on-screen recovery path leads nowhere (and the CLI path is F-001-broken after a pw change). Fallback mode even displays `fallback-no-recovery-key` (fallback-vault.js:91) as the "recovery key".

### F-006 — `audit` command leaks every stored domain via DNS
- `audit_cmd.py:61` `socket.getaddrinfo(domain, 443)` for every rp_id → system resolver/ISP/observer learns the full list of sites you hold passkeys for. Contradicts README ("No third-party servers", "Works offline") and SECURITY.md's threat model. Fix: network check behind an explicit `--dns` opt-in flag.

### F-007 — `pip install -e ./cli` fails (README Quick Start is broken)
- **Evidence (live):** hatchling: `ValueError: Readme path must be within the project directory: ../README.md` (`cli/pyproject.toml:9`). Every fresh user following the README hits this. Fix: move README into cli/ (or symlink) or replace readme field with inline description.

### F-008 — UV (user-verified) flag asserted without per-ceremony verification
- `webauthn.py:60` flags `0x45` / `:103` `0x05` always set the UV bit; fallback same (`fallback-vault.js:153,214`). Verification = master password entered up to `idle_timeout` (default 15 min) ago; per ceremony there's only an "Allow" click (user *presence*). Relying parties that trust `userVerification=true` for step-up auth get a weaker guarantee than the flag promises. Fix: set UV only when a verification event occurred for this ceremony (or honor the RP's `userVerification` requirement with a re-auth prompt).

### F-009 — Hardcoded extension ID breaks native messaging for unpacked installs; docs contradict code
- `manifest.py:12` registers `allowed_origins: chrome-extension://obmjfdinhjjnajapcpkdjignghpjhalm/` only. Unpacked extensions (the documented install path, README §3) get a path-derived ID → Chrome refuses the connection → extension silently degrades into fallback mode (→ F-004). **Live evidence:** this machine's manifest at `%LOCALAPPDATA%\zenith-passkeys\native-manifests\chrome\com.zenith.passkeys.json` carries exactly this hardcoded ID. `SETUP.md` Step 5 tells users to hand-edit `EXTENSION_ID` in manifest.py, contradicting the in-code comment ("permanent ID ... users never have to configure"). Fix: `--extension-id` option on `init` that rewrites the manifest; fail loudly on ID mismatch instead of falling back.

### F-021 — `zenith-passkeys lock` is a placebo
- `lock_cmd.py:6-10` prints "✓ Vault locked... session cleared" while doing **nothing** — the native host is a separate process the CLI cannot reach (only the extension's `lock` action, background.js → host `_do_lock`, actually locks). A user who runs `lock` believes the session is cleared; MEK stays in host memory until idle timeout. Fix: signal the host (lock file / IPC / have host watch for a lock sentinel), or remove the command and point to the popup.

## 🟡 MEDIUM

- **F-010** Empty `rpId` accepted (`host.py:120-121`, `fallback-vault.js:131`): `if not rp_id: return True`. WebAuthn requires rpId to derive from the caller's origin; default it to the effective domain and validate. A forged window message (page can post `__zenith_passkeys__request` directly) with empty rpId can mint `rp_id=""` credentials. Not exploitable against real RPs, but unnecessary surface.
- **F-011** `config --use-keyring` stores the master password in the OS keyring (`config_cmd.py:27`) and **nothing ever reads it** (no `get_password` anywhere). Pure secret exposure, zero benefit. Implement auto-unlock or drop the option.
- **F-012** `import` trusts export files: `Credential(**c_data)` (import_cmd.py:65) — malformed keys → TypeError → fatal panel; no validation of base64/algorithm/counter. Add schema validation with a clean error.
- **F-013** `backup pull` validates only magic/header/min-size (backup_cmd.py:66-72) then overwrites the good local vault after a confirm. Restore to temp, verify a successful unlock with the master password, then replace.
- **F-020** Windows registry writes swallow all errors (`manifest.py:100-101`): failed registration reports success → silent native-messaging breakage (compounds F-009).
- **F-022** Content scripts match `http://*/*` (manifest.json:12,18) — WebAuthn over plain HTTP; MITM-able ceremonies on insecure origins. Restrict to `https:` (localhost needs `host_permissions` exception if desired).

## ℹ️ LOW / HYGIENE

- **F-014** MEK from `vault.create` is immutable `bytes` (vault.py:28,78) — `_lock`'s zeroization (`host.py:43-44`) is a no-op for it; `unlock` correctly returns bytearray. Have `create` return bytearray too. (Python can't guarantee zeroization — document as accepted limit.)
- **F-015** Dead code: `extension/native-client.js` (referenced nowhere), `extension/lib/cbor.js` + `lib/hash-wasm.js` (never imported), `native_host/host_wrapper.py` (manifest points at console script, so ZENITH_DEBUG logging is unreachable), `vault.save()` (only tests call it), `MAGIC` import in vault.py.
- **F-016** ruff baseline: **65 errors** (39 auto-fixable) — unused imports, unsorted blocks, blind `except Exception: pass` (9×), implicit Optional. No lint/typecheck gate in CI (none exists).
- **F-017** Protocol doc drift: `docs/native-messaging-protocol.md` documents `get_assertion → {"assertion":…} | {"candidates":…}` (host returns `credential`), omits `delete_credential`.
- **F-018** `generate_credential_keypair` annotated `tuple[bytes,bytes,bytes]` but returns 4 values (webauthn.py:20-43).
- **F-019** `web_accessible_resources` exposes `content-main.js` to all pages (manifest.json:29-31) — install fingerprinting; not needed for manifest-injected MAIN-world scripts.
- **F-023** `get_status` reports `unlocked: true` whenever the native port is connected (background.js:111-115) regardless of lock state (currently unused by UI, but a trap).

## ✅ Verified-solid (no action)

Argon2id 64MB/t=3/l=4 (OWASP+); AES-256-GCM with header AAD incl. KDF-param tamper detection; header DoS caps (iterations ≤10000, mem ≤2GB, lanes ≤128); 12-byte nonces fresh per write; atomic `.tmp`+`os.replace`+fsync with 0o600; FileLock around read-modify-write; recovery key 160-bit entropy, unambiguous Base32 alphabet; rpId↔origin suffix validation host-side; 1MB message cap; idle auto-lock with gc; private-key bytes zero-filled after assertion (host path); popup/CLI output consistently HTML/markup-escaped (no XSS found); plaintext export gated behind explicit warning+confirm; import 50MB cap; secrets hygiene: no vault/.enc/token files tracked in git (verified `git ls-files`).

## Feature trace matrix

| Feature | UI | Path | Core | Status |
|---|---|---|---|---|
| Create vault | popup + CLI init | create_vault / init | vault.create | ✅ |
| Unlock | popup/confirm/CLI | unlock | vault.unlock | ⚠️ F-002 |
| Lock | popup ✅ / CLI ❌ | lock | host._lock | ⚠️ F-021 |
| Recovery | popup ❌ / CLI ⚠️ | — | unlock_with_recovery | ❌ F-001/F-005 |
| Change password | CLI | — | change_password | ❌ F-001 |
| Register passkey | page→MAIN→ISO→bg→host | create_credential | webauthn | ✅ native / ❌ fallback F-004 |
| Sign-in passkey | same | get_assertion | webauthn | ✅ native / ❌ fallback F-004 |
| List / Delete / Settings | popup + CLI | list/delete/settings | schema | ✅ |
| Export / Import | CLI | — | export/import | ⚠️ F-002, F-012 |
| Backup push/pull | CLI | — | gdrive | ⚠️ F-003, F-013 |
| Audit | CLI | — | — | ⚠️ F-006 |
| Logs | CLI | — | action_log | ✅ |

## Recommended fix order (after your approval)

1. **P0:** F-001 (recovery re-wrap, both flows + regression tests), F-002 (exception contract + tests), F-007 (pyproject readme), F-021 (lock placebo).
2. **P1:** F-009 (extension-ID config + loud failure), F-004 (fallback CBOR/DER or remove fallback ceremonies), F-005 (popup recover action), F-006 (DNS opt-in), F-003 (secret rotation — needs your Google account action).
3. **P2:** F-008 (UV policy decision — owner call), F-010, F-011, F-012, F-013, F-020, F-022.
4. **P3:** hygiene F-014-F-019, F-023, ruff `--fix` + CI gate.

No remediation performed. Awaiting your go-ahead.

---

# Remediation Log (2026-09-09, v1.1.0) — ALL P0/P1/P2 FIXED & VERIFIED

| Finding | Fix | Files | Verification |
|---|---|---|---|
| F-001 🔴 | `change_password` keeps salts/AAD stable; new `set_password_with_recovery` rotates both salts AND re-wraps both slots (recovery stays multi-use) | vault.py, init_cmd.py | live probe: recovery works after change-password AND after recover flow; unit tests added |
| F-002 🔴 | ValueError contract: all 9 commands use `_shared.handle_vault_error`; wrong pw → "Wrong password." | all commands, _shared.py | CLI probe: clean message, no fatal panel; 92/92 tests |
| F-003 🟠 | ⚠️ OWNER ACTION REQUIRED — rotate the Google client_secret; secret still in git history. Code now documents it as user-supplied via gdrive.py (rotation pending) | — | pending owner |
| F-004 🟠 | Fallback mode rebuilt: real CBOR (rewrote lib/cbor.js — original had a fatal ArrayBuffer-concat bug producing strings), COSE keys, raw→DER signature conversion | fallback-vault.js, lib/cbor.js | Node sim + Python RP verification: attestation CBOR-decodes, signature cryptographically verifies |
| F-005 🟠 | `recover_vault` host action + popup recovery form (recovery key + new password fields) | host.py, popup.js/html, background.js | live protocol test #9 PASS |
| F-006 🟠 | DNS check behind `--dns` opt-in flag; audit offline by default | audit_cmd.py | e2e probe 12a/b |
| F-007 🟠 | readme moved into cli/README.md (hatchling-safe) | pyproject.toml, cli/README.md | `pip install -e ./cli` works, `zenith-passkeys --version` → 1.1.0 |
| F-008 🟠 | UV flag set only when password entered ≤5 min ago (host + fallback, matched windows) | host.py, webauthn.py, fallback-vault.js | e2e probes 5a/5b: UV=0 stale, UV=1 fresh |
| F-009 🟠 | `init --extension-id <id>` persists ID to extension_id.txt; registry-write failures now surfaced; sentinel `ZENITH_HOME` env override | manifest.py, init_cmd.py, paths.py | live: init reports registration errors |
| F-021 🟠 | Real cross-process lock: `lock-requested` sentinel file, host polls 1s, writes `lock-ack`, wipes MEK | lock_sentinel.py, host.py, lock_cmd.py | live protocol test #8: running host locks on CLI lock |
| F-010 🟡 | Empty rpId defaults to origin hostname host-side & fallback-side | host.py, fallback-vault.js | e2e probe 5a |
| F-011 🟡 | `--use-keyring` removed (stored password, never read) | config_cmd.py | n/a |
| F-012 🟡 | Import validates every entry (types, fields, sizes, algorithm) before writing | import_cmd.py | probe 12c: invalid file → "Invalid credential #1", nothing written |
| F-013 🟡 | `backup pull` stages backup → unlock-verify → confirm → replace | backup_cmd.py | code-verified (needs gdrive creds for live test) |
| F-014 ⚪ | `create()` returns bytearray MEK (zeroizable) | vault.py | unit test asserts bytearray |
| F-015 ⚪ | Dead code removed: native-client.js, lib/hash-wasm.js | extension/ | grep clean |
| F-016 ⚪ | ruff: 65 → 0 errors | all | `ruff check cli/src/` → All checks passed |
| F-017 ⚪ | Protocol doc updated (recover_vault, delete_credential, correct response shape) + lock sentinel + origin trust | native-messaging-protocol.md | doc matches code |
| F-018 ⚪ | 4-tuple annotation fixed | webauthn.py | ruff |
| F-019 ⚪ | web_accessible_resources dropped | manifest.json | manifest no longer exposes files |
| F-022 🟡 | Content scripts: https + localhost/127.0.0.1 only | manifest.json | manifest |
| F-023 🟡 | `get_status` reports honest unlocked state (port connected ≠ unlocked) | background.js | code |
| UX | Support contact zenithprojects@icloud.com + error code on every failure surface (CLI fatal panel, popup, confirm, host errors) | main.py, popup, confirm, host.py, errors.py | visible in all error paths |

**Extra fixes found during remediation:**
- `lib/cbor.js` ArrayBuffer-concat bug (encoder produced garbage) — would have broken fallback even with the F-004 fix
- `add_credential` now rejects duplicate credential_id (WebAuthn uniqueness)
- `ZENITH_HOME` env override for portable/test isolation
- Stale `lock-ack` cleared per lock request
- CLI `logs` command timezone-aware timestamps

**Gates at close:** pytest 92/92 · ruff 0 errors · `pip install -e ./cli` OK · live native-host protocol test 10/10 PASS · fallback RP-verification PASS (real WebCrypto → Python cbor2 + cryptography verify) · JS syntax checks PASS

**Remaining for owner:** F-003 Google client_secret rotation (Google-side action + purge from git history); Firefox permanent extension signing for store distribution.

