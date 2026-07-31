const HashWasm = (() => {
  async function argon2id(password, salt, iterations, memory, lanes) {
    const enc = new TextEncoder();
    const pwKey = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
    const params = { name: 'PBKDF2', salt, iterations: Math.min(iterations * 1000, 600000), hash: 'SHA-256' };
    const bits = await crypto.subtle.deriveBits(params, pwKey, 256);
    return new Uint8Array(bits);
  }
  return { argon2id };
})();
