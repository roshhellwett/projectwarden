/**
 * Fallback Vault — browser-only mode when native host is unavailable.
 *
 * IMPORTANT: This fallback uses PBKDF2-SHA256 via Web Crypto API (not Argon2id)
 * and stores credentials in chrome.storage.local as JSON. Vaults created in
 * fallback mode are NOT compatible with the CLI's vault.enc binary format.
 *
 * For full compatibility, install the zenith-passkeys CLI package and use
 * the native messaging host. You can export from fallback mode and import
 * into the CLI to migrate.
 */
const ZenithFallback = (() => {
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

  async function getKeyFromPassword(password, salt) {
    const enc = new TextEncoder();
    const pwBytes = enc.encode(password);
    const pwKey = await crypto.subtle.importKey('raw', pwBytes, 'PBKDF2', false, ['deriveKey', 'deriveBits']);
    const key = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256' },
      pwKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
    pwBytes.fill(0);
    return key;
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

  async function getVault() {
    if (unlockedVault) return unlockedVault;
    throw new Error('Vault is locked');
  }

  async function saveVault(vault) {
    if (!sessionKey || !sessionSalt) throw new Error('Vault is locked');
    const data = new TextEncoder().encode(JSON.stringify(vault));
    const encrypted = await encryptWithKey(data, sessionKey, sessionSalt);
    data.fill(0);
    await chrome.storage.local.set({ zenith_vault: base64urlEncode(encrypted) });
    encrypted.fill(0);
    unlockedVault = vault;
  }

  async function createVault(password) {
    const data = await chrome.storage.local.get('zenith_vault');
    if (data.zenith_vault) throw new Error('Vault already exists');
    
    const salt = crypto.getRandomValues(new Uint8Array(16));
    sessionKey = await getKeyFromPassword(password, salt);
    sessionSalt = salt;
    const initialVault = { version: 1, credentials: [], settings: {} };
    await saveVault(initialVault);
    return 'fallback-no-recovery-key';
  }

  async function unlockVault(password) {
    const data = await chrome.storage.local.get('zenith_vault');
    if (!data.zenith_vault) throw new Error('No vault found');
    
    const encrypted = base64urlDecode(data.zenith_vault);
    try {
      const { plain, key, salt } = await decrypt(encrypted, password);
      unlockedVault = JSON.parse(new TextDecoder().decode(plain));
      sessionKey = key;
      sessionSalt = salt;
      plain.fill(0);
      encrypted.fill(0);
      return true;
    } catch (e) {
      throw new Error('Wrong password');
    }
  }

  async function listCredentials() {
    const vault = await getVault();
    return vault.credentials.map(c => ({
      rpId: c.rp_id,
      credentialId: c.credential_id,
      username: c.username,
      createdAt: c.created_at,
      lastUsedAt: c.last_used_at,
      counter: c.counter
    }));
  }

  async function lockVault() {
    unlockedVault = null;
    sessionKey = null;
    sessionSalt = null;
  }

  function isValidRpId(rpId, origin) {
    if (!rpId) return true;
    let hostname;
    try { hostname = new URL(origin).hostname; } catch (e) { return false; }
    return hostname === rpId || hostname.endsWith('.' + rpId);
  }

  async function handleCreate(options, origin) {
    const vault = await getVault();
    const privateKey = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);
    const pubKey = await crypto.subtle.exportKey('raw', privateKey.publicKey);
    const pkcs8 = await crypto.subtle.exportKey('pkcs8', privateKey);
    const credentialId = crypto.getRandomValues(new Uint8Array(32));
    const rpId = options.rp && options.rp.id ? options.rp.id : new URL(origin).hostname;
    if (!isValidRpId(rpId, origin)) throw new Error('Security Error: Invalid rpId for origin');
    const userHandle = options.user && options.user.id ? base64urlDecode(options.user.id) : crypto.getRandomValues(new Uint8Array(16));
    const username = options.user && (options.user.displayName || options.user.name) ? (options.user.displayName || options.user.name) : '';

    const clientData = { type: 'webauthn.create', challenge: options.challenge, origin, crossOrigin: false };
    const clientDataJSON = new TextEncoder().encode(JSON.stringify(clientData));
    const authData = new Uint8Array(37);
    const rpIdHash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(rpId));
    authData.set(new Uint8Array(rpIdHash), 0);
    authData[32] = 0x45;
    authData.set([0, 0, 0, 0], 33);
    const attestedOffset = 37;
    const fullAuthData = new Uint8Array(attestedOffset + 16 + 2 + credentialId.length + pubKey.byteLength);
    fullAuthData.set(authData, 0);
    fullAuthData.set(new Uint8Array(16), attestedOffset);
    fullAuthData.set([0, credentialId.length], attestedOffset + 16);
    fullAuthData.set(credentialId, attestedOffset + 18);
    fullAuthData.set(new Uint8Array(pubKey), attestedOffset + 18 + credentialId.length);

    const attestationObject = { fmt: 'none', attStmt: {}, authData: Array.from(fullAuthData) };
    const pkcs8Arr = new Uint8Array(pkcs8);
    const credEntry = {
      rp_id: rpId,
      credential_id: base64urlEncode(credentialId),
      private_key: base64urlEncode(pkcs8Arr),
      public_key: base64urlEncode(new Uint8Array(pubKey)),
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
          attestationObject: base64urlEncode(new Uint8Array(new TextEncoder().encode(JSON.stringify(attestationObject)))),
          clientDataJSON: base64urlEncode(clientDataJSON),
        },
        authenticatorAttachment: 'platform',
      },
    };
  }

  async function handleGet(options, origin) {
    const vault = await getVault();
    const rpId = options.rpId || new URL(origin).hostname;
    if (!isValidRpId(rpId, origin)) throw new Error('Security Error: Invalid rpId for origin');
    let creds = vault.credentials.filter(c => c.rp_id === rpId);
    if (options.allowCredentials && options.allowCredentials.length) {
      const allowedIds = options.allowCredentials.map(c => c.id);
      creds = creds.filter(c => allowedIds.includes(c.credential_id));
    }
    if (!creds.length) throw new Error('No credentials found');
    const cred = creds[0];
    const newCounter = (cred.counter || 0) + 1;

    const clientData = { type: 'webauthn.get', challenge: options.challenge, origin, crossOrigin: false };
    const clientDataJSON = new TextEncoder().encode(JSON.stringify(clientData));
    const rpIdHash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(rpId));
    const authData = new Uint8Array(37);
    authData.set(new Uint8Array(rpIdHash), 0);
    authData[32] = 0x05;
    const counterBuf = new ArrayBuffer(4);
    new DataView(counterBuf).setUint32(0, newCounter, false);
    authData.set(new Uint8Array(counterBuf), 33);

    const clientDataHash = await crypto.subtle.digest('SHA-256', clientDataJSON);
    const signedData = new Uint8Array(authData.length + new Uint8Array(clientDataHash).length);
    signedData.set(authData, 0);
    signedData.set(new Uint8Array(clientDataHash), authData.length);

    const pkcs8 = base64urlDecode(cred.private_key);
    const privateKey = await crypto.subtle.importKey('pkcs8', pkcs8, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
    const signature = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, signedData);
    pkcs8.fill(0);

    cred.counter = newCounter;
    cred.last_used_at = new Date().toISOString();
    await saveVault(vault);

    return {
      assertion: {
        id: cred.credential_id,
        rawId: cred.credential_id,
        type: 'public-key',
        response: {
          authenticatorData: base64urlEncode(authData),
          clientDataJSON: base64urlEncode(clientDataJSON),
          signature: base64urlEncode(new Uint8Array(signature)),
          userHandle: cred.user_handle,
        },
        authenticatorAttachment: 'platform',
      },
    };
  }

  return { handleCreate, handleGet, createVault, unlockVault, listCredentials, lockVault };
})();
