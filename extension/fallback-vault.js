/**
 * Fallback Vault — browser-only mode when native host is unavailable.
 *
 * SECURITY/COMPAT: This fallback produces SPEC-CONFORMANT WebAuthn
 * structures (audit F-004 fixes):
 *   - attestationObject is CBOR-encoded (lib/cbor.js), not JSON
 *   - the credential public key is embedded as a COSE_Key (not raw)
 *   - signatures are converted from WebCrypto raw r||s to ASN.1 DER
 *
 * Encryption uses PBKDF2-SHA256 (Web Crypto has no Argon2id) with
 * 600,000 iterations. Fallback vaults are stored in chrome.storage.local
 * and are NOT compatible with the CLI's vault.enc binary format — use
 * the CLI/native host for full compatibility.
 */
if (typeof CborEncoder === 'undefined' && typeof importScripts === 'function') {
  try {
    importScripts('lib/cbor.js');
  } catch (e) {
    console.warn('fallback-vault: importScripts failed', e);
  }
}

var cborEncoder = (typeof CborEncoder !== 'undefined') ? new CborEncoder() : null;
function getCborEncoder() {
  if (!cborEncoder && typeof CborEncoder !== 'undefined') {
    cborEncoder = new CborEncoder();
  }
  return cborEncoder;
}

var ZenithFallback = (() => {
  const SUPPORT_EMAIL = 'zenithprojects@icloud.com';
  const UV_FRESHNESS_MS = 5 * 60 * 1000; // matches native host UV window
  const PBKDF2_ITERATIONS = 600000;

  function base64urlEncode(buf) {
    const bytes = new Uint8Array(buf);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function base64urlDecode(str) {
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) str += '=';
    const binary = atob(str);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }

  // ── WebCrypto ECDSA produces raw r||s; WebAuthn needs ASN.1 DER ──
  function _derLength(n) {
    if (n < 0x80) return new Uint8Array([n]);
    if (n < 0x100) return new Uint8Array([0x81, n]);
    return new Uint8Array([0x82, (n >> 8) & 0xff, n & 0xff]);
  }
  function _integerBytes(intBytes) {
    // strip leading zeros; prepend 0x00 if high bit set
    let i = 0;
    while (i < intBytes.length - 1 && intBytes[i] === 0) i++;
    const stripped = intBytes.slice(i);
    if (stripped[0] & 0x80) {
      const out = new Uint8Array(stripped.length + 1);
      out.set(stripped, 1);
      return out;
    }
    return stripped;
  }
  function _integerToDer(intBytes) {
    return _integerBytes(intBytes);
  }
  function ecdsaRawToDer(rawSig) {
    const r = _integerBytes(rawSig.slice(0, 32));
    const s = _integerBytes(rawSig.slice(32));
    const rLen = _derLength(r.length);
    const sLen = _derLength(s.length);
    const innerLen = 1 + rLen.length + r.length + 1 + sLen.length + s.length;
    const seqLen = _derLength(innerLen);
    const out = new Uint8Array(1 + seqLen.length + innerLen);
    let o = 0;
    out[o++] = 0x30; // SEQUENCE
    out.set(seqLen, o); o += seqLen.length;
    out[o++] = 0x02; out.set(rLen, o); o += rLen.length; out.set(r, o); o += r.length;
    out[o++] = 0x02; out.set(sLen, o); o += sLen.length; out.set(s, o);
    return out;
  }

  function getCborEncoder() {
    if (typeof CborEncoder !== 'undefined') return new CborEncoder();
    if (typeof globalThis !== 'undefined' && globalThis.CborEncoder) return new globalThis.CborEncoder();
    if (typeof self !== 'undefined' && self.CborEncoder) return new self.CborEncoder();
    throw new Error('CborEncoder is not available');
  }

  // ── COSE_Key for ES256 (alg -7, EC2, P-256) from raw 65-byte pubkey ──
  function coseKeyFromRaw(rawPub) {
    // raw = 0x04 || X(32) || Y(32)
    if (rawPub.length !== 65 || rawPub[0] !== 0x04) throw new Error('Invalid raw public key');
    const x = rawPub.slice(1, 33);
    const y = rawPub.slice(33);
    const coseMap = new Map([
      [1, 2],      // kty: EC2
      [3, -7],     // alg: ES256
      [-1, 1],     // crv: P-256
      [-2, x],     // x
      [-3, y],     // y
    ]);
    const enc = getCborEncoder();
    return enc.encode(coseMap);
  }

  async function getKeyFromBytes(bytes, salt) {
    const pwKey = await crypto.subtle.importKey('raw', bytes, 'PBKDF2', false, ['deriveKey', 'deriveBits']);
    const key = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256' },
      pwKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
    return key;
  }

  async function getKeyFromPassword(password, salt) {
    const enc = new TextEncoder();
    const pwBytes = enc.encode(password);
    return getKeyFromBytes(pwBytes, salt);
  }

  const RECOVERY_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

  function formatRecoveryKey(raw) {
    let value = 0n;
    for (let i = 0; i < raw.length; i++) {
      value = (value << 8n) | BigInt(raw[i]);
    }
    const chars = [];
    for (let i = 0; i < 32; i++) {
      const shift = 5n * BigInt(31 - i);
      chars.push(RECOVERY_ALPHABET[Number((value >> shift) & 0x1fn)]);
    }
    const groups = [];
    for (let i = 0; i < 32; i += 4) {
      groups.push(chars.slice(i, i + 4).join(''));
    }
    return groups.join('-');
  }

  function parseRecoveryKey(display) {
    const clean = String(display || '').toUpperCase().replace(/[- ]/g, '');
    if (clean.length !== 32) {
      throw new Error(`Recovery key must be 32 characters, got ${clean.length}`);
    }
    let value = 0n;
    for (let i = 0; i < 32; i++) {
      const idx = RECOVERY_ALPHABET.indexOf(clean[i]);
      if (idx === -1) throw new Error(`Invalid character in recovery key: ${clean[i]}`);
      value = (value << 5n) | BigInt(idx);
    }
    const bytes = new Uint8Array(20);
    for (let i = 19; i >= 0; i--) {
      bytes[i] = Number(value & 0xffn);
      value >>= 8n;
    }
    return bytes;
  }

  function generateRecoveryKey() {
    const raw = crypto.getRandomValues(new Uint8Array(20));
    return { raw, display: formatRecoveryKey(raw) };
  }

  async function wrapMek(mekBytes, key) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, mekBytes);
    const out = new Uint8Array(iv.length + ct.byteLength);
    out.set(iv, 0);
    out.set(new Uint8Array(ct), iv.length);
    return out;
  }

  async function unwrapMek(wrappedBytes, key) {
    const iv = wrappedBytes.slice(0, 12);
    const ct = wrappedBytes.slice(12);
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
    return new Uint8Array(plain);
  }

  async function getMekCryptoKey(mekBytes) {
    return crypto.subtle.importKey('raw', mekBytes, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  }

  async function encryptWithKey(data, key, salt) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
    const combined = new Uint8Array(salt.length + iv.length + ct.byteLength);
    combined.set(salt, 0);
    combined.set(iv, salt.length);
    combined.set(new Uint8Array(ct), salt.length + iv.length);
    return combined;
  }

  async function decrypt(data, password) {
    const salt = data.slice(0, 16);
    const iv = data.slice(16, 28);
    const ct = data.slice(28);
    const key = await getKeyFromPassword(password, salt);
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
    return { plain: new Uint8Array(plain), key, salt };
  }

  let unlockedVault = null;
  let sessionKey = null;
  let sessionSalt = null;
  let sessionMek = null;
  let sessionMekKey = null;
  let sessionVaultContainer = null;
  let lastVerifiedAt = 0;

  async function getVault() {
    if (unlockedVault) return unlockedVault;
    throw new Error('Vault is locked');
  }

  const _storage = {
    async get(key) {
      if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
        return new Promise((resolve) => {
          chrome.storage.local.get(key, (res) => resolve(res || {}));
        });
      }
      try {
        if (typeof localStorage !== 'undefined') {
          const val = localStorage.getItem(key);
          return { [key]: val };
        }
      } catch (e) {}
      return {};
    },
    async set(items) {
      if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
        return new Promise((resolve) => {
          chrome.storage.local.set(items, () => resolve());
        });
      }
      try {
        if (typeof localStorage !== 'undefined') {
          for (const [k, v] of Object.entries(items)) {
            localStorage.setItem(k, v);
          }
        }
      } catch (e) {}
    },
  };

  async function vaultExists() {
    const data = await _storage.get('zenith_vault');
    return !!data.zenith_vault;
  }

  async function saveVault(vault) {
    if (!unlockedVault) throw new Error('Vault is locked');
    const data = new TextEncoder().encode(JSON.stringify(vault));

    if (sessionMekKey && sessionVaultContainer) {
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, sessionMekKey, data);
      data.fill(0);

      const payloadBytes = new Uint8Array(iv.length + ct.byteLength);
      payloadBytes.set(iv, 0);
      payloadBytes.set(new Uint8Array(ct), iv.length);

      sessionVaultContainer.payload = base64urlEncode(payloadBytes);
      await _storage.set({ zenith_vault: JSON.stringify(sessionVaultContainer) });
      unlockedVault = vault;
      return;
    }

    // Legacy v1 fallback
    if (!sessionKey || !sessionSalt) throw new Error('Vault is locked');
    const encrypted = await encryptWithKey(data, sessionKey, sessionSalt);
    data.fill(0);
    await _storage.set({ zenith_vault: base64urlEncode(encrypted) });
    encrypted.fill(0);
    unlockedVault = vault;
  }

  async function createVault(password) {
    const data = await _storage.get('zenith_vault');
    if (data.zenith_vault) throw new Error('Vault already exists');
    if (!password || password.length < 8) throw new Error('Password must be at least 8 characters');

    const mek = crypto.getRandomValues(new Uint8Array(32));
    const pwSalt = crypto.getRandomValues(new Uint8Array(16));
    const recSalt = crypto.getRandomValues(new Uint8Array(16));
    const { raw: rawRec, display: displayRec } = generateRecoveryKey();

    const pwKey = await getKeyFromPassword(password, pwSalt);
    const recKey = await getKeyFromBytes(rawRec, recSalt);

    const pwWrapped = await wrapMek(mek, pwKey);
    const recWrapped = await wrapMek(mek, recKey);

    sessionMek = mek;
    sessionMekKey = await getMekCryptoKey(mek);
    lastVerifiedAt = Date.now();

    const initialVault = {
      version: 2,
      credentials: [],
      settings: { idle_timeout_minutes: 15 },
      action_log: []
    };

    sessionVaultContainer = {
      v: 2,
      pwSalt: base64urlEncode(pwSalt),
      recSalt: base64urlEncode(recSalt),
      pwWrapped: base64urlEncode(pwWrapped),
      recWrapped: base64urlEncode(recWrapped),
    };

    unlockedVault = initialVault;
    await saveVault(initialVault);
    return displayRec;
  }

  async function unlockVault(password) {
    const data = await _storage.get('zenith_vault');
    if (!data.zenith_vault) throw new Error('No vault found');

    let container = null;
    try {
      if (typeof data.zenith_vault === 'string' && data.zenith_vault.trim().startsWith('{')) {
        container = JSON.parse(data.zenith_vault);
      }
    } catch (_) {}

    if (container && container.v === 2) {
      const pwSalt = base64urlDecode(container.pwSalt);
      const pwWrapped = base64urlDecode(container.pwWrapped);
      const payloadBytes = base64urlDecode(container.payload);

      let pwKey;
      let mek;
      try {
        pwKey = await getKeyFromPassword(password, pwSalt);
        mek = await unwrapMek(pwWrapped, pwKey);
      } catch (e) {
        throw new Error('Wrong password');
      }

      const mekKey = await getMekCryptoKey(mek);
      const iv = payloadBytes.slice(0, 12);
      const ct = payloadBytes.slice(12);
      const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, mekKey, ct);
      const vault = JSON.parse(new TextDecoder().decode(plain));

      unlockedVault = vault;
      sessionMek = mek;
      sessionMekKey = mekKey;
      sessionVaultContainer = container;
      lastVerifiedAt = Date.now();
      return true;
    }

    // Legacy v1 fallback
    const encrypted = base64urlDecode(data.zenith_vault);
    try {
      const { plain, key, salt } = await decrypt(encrypted, password);
      unlockedVault = JSON.parse(new TextDecoder().decode(plain));
      sessionKey = key;
      sessionSalt = salt;
      lastVerifiedAt = Date.now();
      plain.fill(0);
      encrypted.fill(0);
      return true;
    } catch (e) {
      throw new Error('Wrong password');
    }
  }

  async function recoverVault(recoveryDisplay, newPassword) {
    if (!newPassword || newPassword.length < 8) {
      throw new Error('New password must be at least 8 characters');
    }
    const data = await _storage.get('zenith_vault');
    if (!data.zenith_vault) throw new Error('No vault found');

    let container = null;
    try {
      if (typeof data.zenith_vault === 'string' && data.zenith_vault.trim().startsWith('{')) {
        container = JSON.parse(data.zenith_vault);
      }
    } catch (_) {}

    if (!container || !container.recSalt || !container.recWrapped) {
      throw new Error('This vault does not have recovery enabled');
    }

    const rawRec = parseRecoveryKey(recoveryDisplay);
    const recSalt = base64urlDecode(container.recSalt);
    const recWrapped = base64urlDecode(container.recWrapped);
    const payloadBytes = base64urlDecode(container.payload);

    let recKey;
    let mek;
    try {
      recKey = await getKeyFromBytes(rawRec, recSalt);
      mek = await unwrapMek(recWrapped, recKey);
    } catch (e) {
      throw new Error('Invalid recovery key or corrupted vault');
    }

    const mekKey = await getMekCryptoKey(mek);
    const iv = payloadBytes.slice(0, 12);
    const ct = payloadBytes.slice(12);
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, mekKey, ct);
    const vault = JSON.parse(new TextDecoder().decode(plain));

    // Re-wrap MEK under the new password with a fresh salt
    const newPwSalt = crypto.getRandomValues(new Uint8Array(16));
    const newPwKey = await getKeyFromPassword(newPassword, newPwSalt);
    const newPwWrapped = await wrapMek(mek, newPwKey);

    container.pwSalt = base64urlEncode(newPwSalt);
    container.pwWrapped = base64urlEncode(newPwWrapped);
    // recSalt and recWrapped remain untouched so recovery key continues to work

    unlockedVault = vault;
    sessionMek = mek;
    sessionMekKey = mekKey;
    sessionVaultContainer = container;
    lastVerifiedAt = Date.now();

    await saveVault(vault);
    return { success: true };
  }

  async function rotateRecoveryKey() {
    if (!unlockedVault || !sessionMek || !sessionVaultContainer) {
      throw new Error('Vault is locked');
    }
    const { raw: rawRec, display: displayRec } = generateRecoveryKey();
    const newRecSalt = crypto.getRandomValues(new Uint8Array(16));
    const recKey = await getKeyFromBytes(rawRec, newRecSalt);
    const recWrapped = await wrapMek(sessionMek, recKey);
    sessionVaultContainer.recSalt = base64urlEncode(newRecSalt);
    sessionVaultContainer.recWrapped = base64urlEncode(recWrapped);
    await saveVault(unlockedVault);
    return displayRec;
  }

  async function listCredentials() {
    const vault = await getVault();
    return (vault.credentials || []).map(c => ({
      rpId: c.rp_id,
      credentialId: c.credential_id,
      username: c.username,
      createdAt: c.created_at,
      lastUsedAt: c.last_used_at,
      counter: c.counter
    }));
  }

  async function deleteCredential(credentialId) {
    const vault = await getVault();
    vault.credentials = (vault.credentials || []).filter(c => c.credential_id !== credentialId);
    await saveVault(vault);
    return { success: true };
  }

  async function getSettings() {
    const vault = await getVault();
    return { settings: vault.settings || { idle_timeout_minutes: 15 } };
  }

  async function updateSettings(updates = {}) {
    const vault = await getVault();
    if (!vault.settings) vault.settings = {};
    Object.assign(vault.settings, updates);
    await saveVault(vault);
    return { success: true, settings: vault.settings };
  }

  async function lockVault() {
    unlockedVault = null;
    sessionKey = null;
    sessionSalt = null;
    if (sessionMek) {
      sessionMek.fill(0);
      sessionMek = null;
    }
    sessionMekKey = null;
    sessionVaultContainer = null;
    lastVerifiedAt = 0;
  }

  function _isUnlocked() {
    return unlockedVault !== null;
  }

  function _uvOk() {
    return (Date.now() - lastVerifiedAt) <= UV_FRESHNESS_MS;
  }

  const PUBLIC_SUFFIXES = new Set([
    'com', 'org', 'net', 'edu', 'gov', 'io', 'dev', 'app',
    'co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'com.au', 'net.au', 'org.au',
    'co.jp', 'ne.jp', 'com.br', 'co.in', 'net.in', 'co.nz', 'co.za',
    'github.io', 'gitlab.io', 'pages.dev', 'workers.dev', 'vercel.app',
    'netlify.app', 'onrender.com', 'fly.dev', 'herokuapp.com',
    'azurewebsites.net', 'appspot.com', 'firebaseapp.com', 'web.app',
    'cloudfront.net', 'glitch.me', 'surge.sh'
  ]);

  function isValidRpId(rpId, origin) {
    let hostname;
    try { hostname = new URL(origin).hostname.toLowerCase(); } catch (e) { return false; }
    if (!rpId) return true;
    rpId = rpId.toLowerCase().replace(/^\.+|\.+$/g, '');
    if (['localhost', '127.0.0.1', '::1'].includes(hostname)) {
      return ['localhost', '127.0.0.1', '::1'].includes(rpId);
    }
    if (!rpId.includes('.') || PUBLIC_SUFFIXES.has(rpId)) {
      return false;
    }
    return hostname === rpId || hostname.endsWith('.' + rpId);
  }

  function effectiveRpId(options, origin) {
    const rpId = (options.rp && options.rp.id) || options.rpId || '';
    return rpId || new URL(origin).hostname;
  }

  async function handleCreate(options, origin) {
    const vault = await getVault();
    const rpId = effectiveRpId(options, origin);
    if (!isValidRpId(rpId, origin)) throw new Error('Security Error: Invalid rpId for origin');

    const keyPair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);
    const rawPub = new Uint8Array(await crypto.subtle.exportKey('raw', keyPair.publicKey));
    const pkcs8 = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
    const credentialId = crypto.getRandomValues(new Uint8Array(32));
    const userHandle = options.user && options.user.id ? base64urlDecode(options.user.id) : crypto.getRandomValues(new Uint8Array(16));
    const username = options.user && (options.user.displayName || options.user.name) ? (options.user.displayName || options.user.name) : '';

    // ── Conformant attestation: CBOR with proper authData ──
    const rpIdHash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(rpId));
    const flags = (0x45 & ~0x04) | (_uvOk() ? 0x04 : 0); // UP|AT (+UV only if fresh)
    const counter = new Uint8Array(4); // 0
    const coseKey = new Uint8Array(coseKeyFromRaw(rawPub));
    const aaguid = new Uint8Array(16);
    const credIdLen = new Uint8Array([0, credentialId.length]);

    const authData = new Uint8Array(32 + 1 + 4 + 16 + 2 + credentialId.length + coseKey.length);
    let o = 0;
    authData.set(new Uint8Array(rpIdHash), 0); o += 32;
    authData[o++] = flags;
    authData.set(counter, o); o += 4;
    authData.set(aaguid, o); o += 16;
    authData.set(credIdLen, o); o += 2;
    authData.set(credentialId, o); o += credentialId.length;
    authData.set(coseKey, o);

    const enc = getCborEncoder();
    const attestationObject = enc.encode(new Map([
      ['fmt', 'none'],
      ['attStmt', new Map()],
      ['authData', authData],
    ]));

    const clientData = { type: 'webauthn.create', challenge: options.challenge, origin, crossOrigin: false };
    const clientDataJSON = new TextEncoder().encode(JSON.stringify(clientData));

    const pkcs8Arr = new Uint8Array(pkcs8);
    const credEntry = {
      rp_id: rpId,
      credential_id: base64urlEncode(credentialId),
      private_key: base64urlEncode(pkcs8Arr),
      public_key: base64urlEncode(rawPub), // raw 65-byte key (fallback-specific)
      public_key_cose: base64urlEncode(coseKey),
      user_handle: base64urlEncode(userHandle),
      username,
      counter: 0,
      created_at: new Date().toISOString(),
      last_used_at: null,
      algorithm: -7,
    };
    pkcs8Arr.fill(0);

    vault.credentials.push(credEntry);
    await saveVault(vault);

    return {
      credential: {
        id: credEntry.credential_id,
        rawId: base64urlEncode(credentialId),
        type: 'public-key',
        response: {
          attestationObject: base64urlEncode(attestationObject),
          clientDataJSON: base64urlEncode(clientDataJSON),
          authenticatorData: base64urlEncode(authData),
        },
        authenticatorAttachment: 'platform',
      },
    };
  }

  async function handleGet(options, origin) {
    const vault = await getVault();
    const rpId = effectiveRpId(options, origin);
    if (!isValidRpId(rpId, origin)) throw new Error('Security Error: Invalid rpId for origin');
    let creds = vault.credentials.filter(c => c.rp_id === rpId);
    if (options.allowCredentials && options.allowCredentials.length) {
      const allowedIds = options.allowCredentials.map(c => c.id);
      creds = creds.filter(c => allowedIds.includes(c.credential_id));
    }
    // excludeCredentials: prefer a credential the RP did not exclude
    if (options.excludeCredentials && options.excludeCredentials.length) {
      const excluded = options.excludeCredentials.map(c => c.id);
      const nonExcluded = creds.filter(c => !excluded.includes(c.credential_id));
      if (nonExcluded.length) creds = nonExcluded;
    }
    // If a specific credential was chosen by the user in the autofill dropdown
    if (options.selectedCredentialId) {
      const selected = creds.find(c => c.credential_id === options.selectedCredentialId);
      if (selected) creds = [selected];
    }
    if (!creds.length) throw new Error('No credentials found');
    const cred = creds[0];
    const newCounter = (cred.counter || 0) + 1;

    const clientData = { type: 'webauthn.get', challenge: options.challenge, origin, crossOrigin: false };
    const clientDataJSON = new TextEncoder().encode(JSON.stringify(clientData));
    const rpIdHash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(rpId));
    const authData = new Uint8Array(37);
    authData.set(new Uint8Array(rpIdHash), 0);
    authData[32] = (0x01) | (_uvOk() ? 0x04 : 0); // UP (+UV only if fresh)
    const counterBuf = new ArrayBuffer(4);
    new DataView(counterBuf).setUint32(0, newCounter, false);
    authData.set(new Uint8Array(counterBuf), 33);

    const clientDataHash = await crypto.subtle.digest('SHA-256', clientDataJSON);
    const signedData = new Uint8Array(authData.length + clientDataHash.byteLength);
    signedData.set(authData, 0);
    signedData.set(new Uint8Array(clientDataHash), authData.length);

    const pkcs8 = base64urlDecode(cred.private_key);
    const privateKey = await crypto.subtle.importKey('pkcs8', pkcs8, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
    const rawSig = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, signedData));
    const derSig = ecdsaRawToDer(rawSig);
    pkcs8.fill(0);

    cred.counter = newCounter;
    cred.last_used_at = new Date().toISOString();
    await saveVault(vault);

    return {
      credential: {
        id: cred.credential_id,
        rawId: cred.credential_id,
        type: 'public-key',
        response: {
          authenticatorData: base64urlEncode(authData),
          clientDataJSON: base64urlEncode(clientDataJSON),
          signature: base64urlEncode(derSig),
          userHandle: cred.user_handle,
        },
        authenticatorAttachment: 'platform',
      },
    };
  }

  async function changePassword(oldPassword, newPassword) {
    if (!unlockedVault) throw new Error('Vault is locked');
    if (!newPassword || newPassword.length < 8) throw new Error('New password must be at least 8 characters');
    const newSalt = crypto.getRandomValues(new Uint8Array(16));
    const newKey = await getKeyFromPassword(newPassword, newSalt);
    sessionKey = newKey;
    sessionSalt = newSalt;
    lastVerifiedAt = Date.now();
    await saveVault(unlockedVault);
    return { success: true };
  }

  async function getAuditReport(unusedDays = 90) {
    const vault = await getVault();
    const now = Date.now();
    const msPerDay = 24 * 60 * 60 * 1000;
    const issues = [];
    for (const c of (vault.credentials || [])) {
      if (c.last_used_at) {
        const diffDays = Math.floor((now - new Date(c.last_used_at).getTime()) / msPerDay);
        if (diffDays >= unusedDays) {
          issues.push({
            type: 'stale',
            severity: 'low',
            rpId: c.rp_id,
            username: c.username,
            credentialId: c.credential_id,
            detail: `Not used in ${diffDays} days`
          });
        }
      }
    }
    const seen = {};
    for (const c of (vault.credentials || [])) {
      const key = (c.rp_id || '') + '::' + (c.username || '');
      if (seen[key]) {
        issues.push({
          type: 'duplicate',
          severity: 'medium',
          rpId: c.rp_id,
          username: c.username,
          credentialId: c.credential_id,
          detail: 'Multiple passkeys registered for same account'
        });
      }
      seen[key] = true;
    }
    const total = (vault.credentials || []).length;
    const deduction = issues.filter(i => i.severity === 'low').length * 5 + issues.filter(i => i.severity === 'medium').length * 15;
    const score = total > 0 ? Math.max(0, 100 - deduction) : 100;
    const grade = score >= 90 ? 'A' : (score >= 75 ? 'B' : (score >= 60 ? 'C' : 'D'));
    return { issues, healthScore: score, grade, totalCredentials: total };
  }

  async function getActionLogs() {
    const vault = await getVault();
    const logs = [...(vault.action_log || [])].reverse();
    return { logs };
  }

  async function getBackupBlob() {
    const vault = await getVault();
    const jsonStr = JSON.stringify(vault);
    const enc = new TextEncoder().encode(jsonStr);
    const hashBuf = await crypto.subtle.digest('SHA-256', enc);
    const shaHex = Array.from(new Uint8Array(hashBuf)).map(b => b.toString(16).padStart(2, '0')).join('');
    const b64 = btoa(unescape(encodeURIComponent(jsonStr)));
    const dateStr = new Date().toISOString().slice(0, 10);
    return {
      backupBlob: b64,
      sha256: shaHex,
      size: enc.byteLength,
      credentialCount: (vault.credentials || []).length,
      filename: `zenith-browser-vault-backup-${dateStr}.json`
    };
  }

  async function restoreBackupBlob(b64) {
    try {
      const jsonStr = decodeURIComponent(escape(atob(b64)));
      const parsed = JSON.parse(jsonStr);
      if (!parsed.credentials || !Array.isArray(parsed.credentials)) {
        throw new Error('Invalid backup file structure');
      }
      const vault = await getVault();
      vault.credentials = parsed.credentials;
      await saveVault(vault);
      return { success: true, credentialCount: vault.credentials.length };
    } catch (e) {
      throw new Error(`Restore failed: ${e.message}`);
    }
  }

  async function exportVault(password) {
    const vault = await getVault();
    const exportData = {
      version: 1,
      exported_at: new Date().toISOString(),
      credentials: vault.credentials || []
    };
    const jsonStr = JSON.stringify(exportData, null, 2);

    if (password && password.length >= 8) {
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const key = await getKeyFromPassword(password, salt);
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(jsonStr));
      const encContainer = {
        format: 'zenith-encrypted-export',
        version: 1,
        kdf: 'pbkdf2',
        iterations: PBKDF2_ITERATIONS,
        salt: base64urlEncode(salt),
        nonce: base64urlEncode(iv),
        ciphertext: base64urlEncode(new Uint8Array(ct))
      };
      return {
        data: JSON.stringify(encContainer, null, 2),
        encrypted: true,
        credentialCount: (vault.credentials || []).length
      };
    }

    return {
      data: jsonStr,
      encrypted: false,
      credentialCount: (vault.credentials || []).length
    };
  }

  async function decryptEncryptedExport(container, password) {
    if (!container || container.format !== 'zenith-encrypted-export') {
      throw new Error('Invalid encrypted export format');
    }
    if (container.kdf === 'argon2id') {
      throw new Error('This export was encrypted with Argon2id. Please import it using the Zenith native host CLI.');
    }
    const salt = base64urlDecode(container.salt);
    const nonce = base64urlDecode(container.nonce);
    const ciphertext = base64urlDecode(container.ciphertext);
    const key = await getKeyFromPassword(password, salt);
    try {
      const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, key, ciphertext);
      const jsonStr = new TextDecoder().decode(pt);
      const parsed = JSON.parse(jsonStr);
      return parsed.credentials || (Array.isArray(parsed) ? parsed : []);
    } catch (e) {
      throw new Error('Incorrect export password or corrupted export file');
    }
  }

  async function importVault(credentialsList, password) {
    const vault = await getVault();
    let list = credentialsList;
    if (credentialsList && typeof credentialsList === 'object' && !Array.isArray(credentialsList)) {
      if (credentialsList.encrypted_export || credentialsList.format === 'zenith-encrypted-export') {
        const container = credentialsList.encrypted_export || credentialsList;
        const pw = password || credentialsList.password;
        if (!pw) throw new Error('Password required for encrypted export');
        list = await decryptEncryptedExport(container, pw);
      } else if (Array.isArray(credentialsList.credentials)) {
        list = credentialsList.credentials;
      }
    }
    if (!Array.isArray(list)) throw new Error('Expected credentials array');
    let count = 0;
    for (const c of list) {
      const rpId = c.rp_id || c.rpId;
      const credId = c.credential_id || c.credentialId;
      const username = c.username;
      if (!rpId || !credId || !username) continue;
      const normalized = {
        rp_id: rpId,
        credential_id: credId,
        username: username,
        user_handle: c.user_handle || c.userHandle || '',
        private_key: c.private_key || c.privateKey || '',
        public_key: c.public_key || c.publicKey || '',
        algorithm: c.algorithm || -7,
        counter: c.counter || 0,
        created_at: c.created_at || c.createdAt || new Date().toISOString(),
        last_used_at: c.last_used_at || c.lastUsedAt || null
      };
      vault.credentials = (vault.credentials || []).filter(x => !(x.rp_id === rpId && x.username === username));
      vault.credentials.push(normalized);
      count++;
    }
    await saveVault(vault);
    return { success: true, importedCount: count, totalCredentials: vault.credentials.length };
  }

  const instance = {
    handleCreate, handleGet, createVault, unlockVault, recoverVault, rotateRecoveryKey, listCredentials,
    lockVault, _isUnlocked, _uvOk, deleteCredential, changePassword,
    getSettings, updateSettings,
    getAuditReport, getActionLogs, getBackupBlob, restoreBackupBlob,
    exportVault, importVault, decryptEncryptedExport, vaultExists, SUPPORT_EMAIL,
  };

  if (typeof self !== 'undefined') self.ZenithFallback = instance;
  if (typeof globalThis !== 'undefined') globalThis.ZenithFallback = instance;
  if (typeof module !== 'undefined' && module.exports) module.exports = instance;
  return instance;
})();
