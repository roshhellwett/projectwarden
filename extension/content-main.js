(function () {
  const PREFIX = '__zenith_passkeys__';
  const TIMEOUT_MS = 120000;

  const originalCreate = navigator.credentials.create.bind(navigator.credentials);
  const originalGet = navigator.credentials.get.bind(navigator.credentials);

  function toBase64url(buf) {
    const bytes = new Uint8Array(buf);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function fromBase64url(str) {
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) str += '=';
    const binary = atob(str);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  function serializeOptions(options) {
    const raw = JSON.parse(JSON.stringify(options));
    if (raw.publicKey) {
      if (raw.publicKey.challenge) raw.publicKey.challenge = toBase64url(raw.publicKey.challenge);
      if (raw.publicKey.user && raw.publicKey.user.id) raw.publicKey.user.id = toBase64url(raw.publicKey.user.id);
      if (raw.publicKey.allowCredentials) {
        raw.publicKey.allowCredentials.forEach(c => {
          if (c.id) c.id = toBase64url(c.id);
        });
      }
      if (raw.publicKey.excludeCredentials) {
        raw.publicKey.excludeCredentials.forEach(c => {
          if (c.id) c.id = toBase64url(c.id);
        });
      }
    }
    return raw;
  }

  function deserializeCredential(data) {
    const cred = {
      id: data.id,
      rawId: typeof data.rawId === 'string' ? fromBase64url(data.rawId) : data.rawId,
      type: data.type,
      getClientExtensionResults: () => ({}),
    };
    if (data.response) {
      cred.response = {};
      if (data.response.attestationObject) {
        cred.response.attestationObject = fromBase64url(data.response.attestationObject);
      }
      if (data.response.clientDataJSON) {
        cred.response.clientDataJSON = fromBase64url(data.response.clientDataJSON);
      }
      if (data.response.authenticatorData) {
        cred.response.authenticatorData = fromBase64url(data.response.authenticatorData);
      }
      if (data.response.signature) {
        cred.response.signature = fromBase64url(data.response.signature);
      }
      if (data.response.userHandle) {
        cred.response.userHandle = fromBase64url(data.response.userHandle);
      }
    }
    return cred;
  }

  function postAndWait(action, options, origin) {
    return new Promise((resolve, reject) => {
      const requestId = Date.now() + Math.random();
      const handler = (event) => {
        if (event.source !== window) return;
        if (event.data && event.data.type === PREFIX + '_response' && event.data.requestId === requestId) {
          window.removeEventListener('message', handler);
          if (event.data.error) {
            reject(new Error(event.data.error));
          } else {
            resolve(event.data.result);
          }
        }
      };
      window.addEventListener('message', handler);
      window.postMessage({
        type: PREFIX + '_request',
        requestId,
        action,
        options,
        origin,
      }, '*');
      setTimeout(() => {
        window.removeEventListener('message', handler);
        reject(new Error('Timeout waiting for Zenith Passkeys confirmation'));
      }, TIMEOUT_MS);
    });
  }

  navigator.credentials.create = async function (options) {
    if (!options || !options.publicKey) {
      return originalCreate(options);
    }
    const serialized = serializeOptions(options);
    const result = await postAndWait('create', serialized.publicKey, window.location.origin);
    return deserializeCredential(result.credential);
  };

  navigator.credentials.get = async function (options) {
    if (!options || !options.publicKey) {
      return originalGet(options);
    }
    const serialized = serializeOptions(options);
    const result = await postAndWait('get', serialized.publicKey, window.location.origin);
    return deserializeCredential(result.assertion);
  };
})();
