/**
 * hash-wasm.js — PBKDF2 fallback for browser environments
 *
 * NOTE: Web Crypto API does not natively support Argon2id.
 * This module provides a PBKDF2-SHA256 based key derivation as a fallback
 * for the browser extension's fallback mode (when the native host is unavailable).
 *
 * Vaults created with this fallback KDF use a different key derivation than
 * the CLI's Argon2id. They are stored in chrome.storage.local and are NOT
 * compatible with the CLI's vault.enc format.
 *
 * For full security and CLI compatibility, install the zenith-passkeys CLI
 * and use the native messaging host.
 */
const HashWasm = (() => {
  async function pbkdf2Derive(password, salt, iterations, outputBits) {
    const enc = new TextEncoder();
    const pwKey = await crypto.subtle.importKey(
      'raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']
    );
    const params = {
      name: 'PBKDF2',
      salt,
      iterations: Math.min(iterations * 1000, 600000),
      hash: 'SHA-256',
    };
    const bits = await crypto.subtle.deriveBits(params, pwKey, outputBits);
    return new Uint8Array(bits);
  }

  return { pbkdf2Derive };
})();
