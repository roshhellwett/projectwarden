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
    const pub = options.publicKey;
    if (!pub) return options;
    
    // Convert ArrayBuffers to base64url strings BEFORE cloning so JSON stringify works
    const serializedPub = { ...pub };
    
    if (!serializedPub.rpId) {
      serializedPub.rpId = window.location.hostname;
    }
    
    if (pub.challenge) {
      serializedPub.challenge = toBase64url(pub.challenge);
    }
    if (pub.user && pub.user.id) {
      serializedPub.user = { ...pub.user, id: toBase64url(pub.user.id) };
    }
    if (pub.allowCredentials) {
      serializedPub.allowCredentials = pub.allowCredentials.map(c => ({
        ...c,
        id: typeof c.id === 'string' ? c.id : (c.id ? toBase64url(c.id) : c.id)
      }));
    }
    if (pub.excludeCredentials) {
      serializedPub.excludeCredentials = pub.excludeCredentials.map(c => ({
        ...c,
        id: typeof c.id === 'string' ? c.id : (c.id ? toBase64url(c.id) : c.id)
      }));
    }
    
    const raw = JSON.parse(JSON.stringify(options));
    raw.publicKey = serializedPub;
    return raw;
  }

  function deserializeCredential(data) {
    const cred = {
      id: data.id,
      rawId: typeof data.rawId === 'string' ? fromBase64url(data.rawId) : data.rawId,
      type: data.type,
      authenticatorAttachment: data.authenticatorAttachment || 'platform',
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
      
      const authData = data.response.authenticatorData ? fromBase64url(data.response.authenticatorData) : new ArrayBuffer(0);
      const pubKeyDer = data.response.publicKeyDer ? fromBase64url(data.response.publicKeyDer) : new ArrayBuffer(0);
      
      if (data.response.signature) {
        cred.response.signature = fromBase64url(data.response.signature);
      }
      if (data.response.userHandle) {
        cred.response.userHandle = fromBase64url(data.response.userHandle);
      }
      
      cred.response.getTransports = () => ['internal'];
      cred.response.getAuthenticatorData = () => authData;
      cred.response.getPublicKey = () => pubKeyDer;
      cred.response.getPublicKeyAlgorithm = () => -7;
      
      if (data.response.attestationObject) {
        Object.setPrototypeOf(cred.response, AuthenticatorAttestationResponse.prototype);
      } else {
        Object.setPrototypeOf(cred.response, AuthenticatorAssertionResponse.prototype);
      }
    }
    Object.setPrototypeOf(cred, PublicKeyCredential.prototype);
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
