(function () {
  'use strict';
  const PREFIX = '__zenith_passkeys__';
  const TIMEOUT_MS = 120000;

  // ── Save references to the original WebAuthn methods ──────────────
  // Bind them to navigator.credentials so they keep the correct `this`.
  const CredProto = window.CredentialsContainer && window.CredentialsContainer.prototype;
  const credContainer = typeof navigator !== 'undefined' ? navigator.credentials : null;
  const originalCreate = (credContainer && credContainer.create) ? credContainer.create.bind(credContainer) : null;
  const originalGet = (credContainer && credContainer.get) ? credContainer.get.bind(credContainer) : null;

  // ── Base64url helpers ─────────────────────────────────────────────
  function toBase64url(buf) {
    if (!buf) return '';
    if (typeof buf === 'string') return buf;
    const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function fromBase64url(str) {
    if (!str) return new ArrayBuffer(0);
    if (str instanceof ArrayBuffer) return str;
    if (ArrayBuffer.isView(str)) return str.buffer.slice(str.byteOffset, str.byteOffset + str.byteLength);
    str = String(str).replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) str += '=';
    const binary = atob(str);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  // ── Serialization: convert ArrayBuffers to base64url for messaging ──
  // Built directly — no JSON.parse(JSON.stringify()) round-trip that
  // would silently destroy ArrayBuffer / TypedArray properties.
  function serializePublicKey(pub) {
    const out = {};

    // Copy all scalar/object properties, converting known ArrayBuffer fields
    for (const key of Object.keys(pub)) {
      const val = pub[key];
      if (val instanceof ArrayBuffer || ArrayBuffer.isView(val)) {
        out[key] = toBase64url(val);
      } else if (key === 'user' && val && typeof val === 'object') {
        out[key] = { ...val };
        if (val.id instanceof ArrayBuffer || ArrayBuffer.isView(val.id)) {
          out[key].id = toBase64url(val.id);
        }
      } else if ((key === 'allowCredentials' || key === 'excludeCredentials') && Array.isArray(val)) {
        out[key] = val.map(c => {
          const copy = { ...c };
          if (c.id instanceof ArrayBuffer || ArrayBuffer.isView(c.id)) {
            copy.id = toBase64url(c.id);
          }
          return copy;
        });
      } else {
        // Primitive values, plain objects — copy as-is
        out[key] = val;
      }
    }

    // Default rpId to the page hostname if not set (WebAuthn spec default)
    if (!out.rpId) {
      out.rpId = window.location.hostname;
    }
    if (out.rp && !out.rp.id) {
      out.rp.id = window.location.hostname;
    }

    return out;
  }

  // ── Deserialization: rebuild a spec-conformant PublicKeyCredential ──
  // WebIDL platform objects (PublicKeyCredential, AuthenticatorAssertionResponse,
  // AuthenticatorAttestationResponse) have native C++ getters and a native toJSON()
  // on their prototypes. If an emulated object delegates to the native getters or
  // native toJSON without possessing the internal C++ platform slots, V8 immediately
  // throws "TypeError: Illegal invocation".
  //
  // To avoid this, EVERY property (authenticatorData, clientDataJSON, signature,
  // userHandle, toJSON, etc.) MUST be defined as an OWN property on the instance so
  // that property lookup never falls through to the native prototype getters.
  function deserializeCredential(data) {
    if (!data) return null;

    const rawId = typeof data.rawId === 'string'
      ? fromBase64url(data.rawId)
      : (data.rawId instanceof ArrayBuffer ? data.rawId : fromBase64url(data.id));

    const isAttestation = !!(data.response && data.response.attestationObject);
    const responseObj = {};

    // 1. clientDataJSON (common to both attestation and assertion)
    responseObj.clientDataJSON = (data.response && data.response.clientDataJSON)
      ? fromBase64url(data.response.clientDataJSON)
      : new ArrayBuffer(0);

    if (isAttestation) {
      // ── AuthenticatorAttestationResponse ──
      responseObj.attestationObject = fromBase64url(data.response.attestationObject);

      const authData = (data.response && data.response.authenticatorData)
        ? fromBase64url(data.response.authenticatorData)
        : new ArrayBuffer(0);
      const pubKeyDer = (data.response && data.response.publicKeyDer)
        ? fromBase64url(data.response.publicKeyDer)
        : (data.response && data.response.publicKey ? fromBase64url(data.response.publicKey) : null);
      const alg = (data.response && data.response.publicKeyAlgorithm) || -7;
      const transports = (data.response && Array.isArray(data.response.transports))
        ? data.response.transports
        : ['internal'];

      responseObj.authenticatorData = authData;
      responseObj.getAuthenticatorData = () => authData;
      responseObj.getTransports = () => [...transports];
      responseObj.transports = [...transports];
      responseObj.getPublicKey = () => pubKeyDer;
      responseObj.publicKey = pubKeyDer;
      responseObj.getPublicKeyAlgorithm = () => alg;
      responseObj.publicKeyAlgorithm = alg;

      responseObj.toJSON = function () {
        return {
          clientDataJSON: toBase64url(responseObj.clientDataJSON),
          attestationObject: toBase64url(responseObj.attestationObject),
          transports: responseObj.getTransports(),
          authenticatorData: toBase64url(responseObj.authenticatorData),
          publicKeyAlgorithm: responseObj.getPublicKeyAlgorithm(),
          ...(responseObj.publicKey ? { publicKey: toBase64url(responseObj.publicKey) } : {}),
        };
      };

      if (typeof AuthenticatorAttestationResponse !== 'undefined' && AuthenticatorAttestationResponse.prototype) {
        Object.setPrototypeOf(responseObj, AuthenticatorAttestationResponse.prototype);
      }
    } else {
      // ── AuthenticatorAssertionResponse ──
      const authData = (data.response && data.response.authenticatorData)
        ? fromBase64url(data.response.authenticatorData)
        : new ArrayBuffer(0);
      const signature = (data.response && data.response.signature)
        ? fromBase64url(data.response.signature)
        : new ArrayBuffer(0);
      const userHandle = (data.response && data.response.userHandle && data.response.userHandle.length > 0)
        ? fromBase64url(data.response.userHandle)
        : null;

      responseObj.authenticatorData = authData;
      responseObj.getAuthenticatorData = () => authData;
      responseObj.signature = signature;
      responseObj.userHandle = userHandle;

      responseObj.toJSON = function () {
        return {
          clientDataJSON: toBase64url(responseObj.clientDataJSON),
          authenticatorData: toBase64url(responseObj.authenticatorData),
          signature: toBase64url(responseObj.signature),
          userHandle: responseObj.userHandle ? toBase64url(responseObj.userHandle) : null,
        };
      };

      if (typeof AuthenticatorAssertionResponse !== 'undefined' && AuthenticatorAssertionResponse.prototype) {
        Object.setPrototypeOf(responseObj, AuthenticatorAssertionResponse.prototype);
      }
    }

    const cred = {
      id: data.id,
      rawId: rawId,
      type: data.type || 'public-key',
      authenticatorAttachment: data.authenticatorAttachment || 'platform',
      response: responseObj,
      clientExtensionResults: {},
      getClientExtensionResults: () => ({}),
      toJSON: function () {
        return {
          id: this.id,
          rawId: toBase64url(this.rawId),
          response: typeof this.response.toJSON === 'function' ? this.response.toJSON() : {},
          authenticatorAttachment: this.authenticatorAttachment,
          clientExtensionResults: typeof this.getClientExtensionResults === 'function' ? this.getClientExtensionResults() : {},
          type: this.type,
        };
      },
    };

    if (typeof PublicKeyCredential !== 'undefined' && PublicKeyCredential.prototype) {
      Object.setPrototypeOf(cred, PublicKeyCredential.prototype);
    }

    return cred;
  }

  // ── Message channel to isolated content script ────────────────────
  function postAndWait(action, options, origin, signal) {
    return new Promise((resolve, reject) => {
      if (signal && signal.aborted) {
        return reject(new DOMException('The operation was aborted.', 'AbortError'));
      }

      const requestId = crypto.randomUUID();
      const abortHandler = () => {
        cleanup();
        reject(new DOMException('The operation was aborted.', 'AbortError'));
      };

      const handler = (event) => {
        if (event.source !== window) return;
        if (event.data && event.data.type === PREFIX + '_response' && event.data.requestId === requestId) {
          cleanup();
          if (event.data.error) {
            reject(new DOMException(event.data.error, 'NotAllowedError'));
          } else {
            resolve(event.data.result);
          }
        }
      };

      function cleanup() {
        window.removeEventListener('message', handler);
        clearTimeout(timer);
        if (signal) {
          signal.removeEventListener('abort', abortHandler);
        }
      }

      window.addEventListener('message', handler);
      if (signal) {
        signal.addEventListener('abort', abortHandler);
      }

      window.postMessage({
        type: PREFIX + '_request',
        requestId,
        action,
        options,
        origin,
      }, '*');

      const timer = setTimeout(() => {
        cleanup();
        reject(new DOMException('Timeout waiting for Zenith Passkeys confirmation', 'NotAllowedError'));
      }, TIMEOUT_MS);
    });
  }

  // ── Zenith create() handler ───────────────────────────────────────
  async function zenithCreate(options) {
    if (!options || !options.publicKey) {
      return originalCreate ? originalCreate(options) : Promise.reject(new DOMException('WebAuthn not supported', 'NotSupportedError'));
    }
    if (options.signal && options.signal.aborted) {
      throw new DOMException('The operation was aborted.', 'AbortError');
    }
    const serialized = serializePublicKey(options.publicKey);
    const result = await postAndWait('create', serialized, window.location.origin, options.signal);
    return deserializeCredential(result.credential);
  }

  // ── Candidate Query Channel ───────────────────────────────────────
  function queryCandidates(rpId) {
    return new Promise((resolve) => {
      const requestId = crypto.randomUUID();
      const timer = setTimeout(() => {
        window.removeEventListener('message', handler);
        resolve([]);
      }, 1500);

      const handler = (event) => {
        if (event.source !== window || !event.data) return;
        if (event.data.type === PREFIX + '_get_candidates_response' && event.data.requestId === requestId) {
          clearTimeout(timer);
          window.removeEventListener('message', handler);
          resolve(event.data.candidates || []);
        }
      };

      window.addEventListener('message', handler);
      window.postMessage({
        type: PREFIX + '_get_candidates',
        requestId,
        rpId,
      }, '*');
    });
  }

  // ── In-Page Autofill Overlay (Shadow DOM) ─────────────────────────
  let activeAutofillHost = null;
  let activeInputElement = null;

  function hideAutofillDropdown() {
    if (activeAutofillHost) {
      activeAutofillHost.remove();
      activeAutofillHost = null;
      activeInputElement = null;
    }
  }

  function isCandidateInput(el) {
    if (!el || el.tagName !== 'INPUT') return false;
    const type = (el.type || 'text').toLowerCase();
    if (['password', 'hidden', 'checkbox', 'radio', 'submit', 'button', 'file'].includes(type)) return false;
    const auto = (el.getAttribute('autocomplete') || '').toLowerCase();
    if (auto.includes('webauthn') || auto.includes('username') || auto.includes('email')) return true;
    const name = (el.name || '').toLowerCase();
    const id = (el.id || '').toLowerCase();
    return name.includes('user') || name.includes('login') || name.includes('email') ||
           id.includes('user') || id.includes('login') || id.includes('email') ||
           type === 'email' || type === 'text';
  }

  const ZENITH_LOGO_DATA_URL = 'data:image/png;base64,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';

  function renderAutofillDropdown(inputElement, candidates, onSelect) {
    if (!inputElement || !candidates || candidates.length === 0) return;
    if (activeAutofillHost && activeInputElement === inputElement) return;
    hideAutofillDropdown();

    activeInputElement = inputElement;
    const host = document.createElement('div');
    host.id = 'zenith-autofill-host';
    host.style.position = 'absolute';
    host.style.top = '0';
    host.style.left = '0';
    host.style.width = '100%';
    host.style.pointerEvents = 'none';
    host.style.zIndex = '2147483647';

    const shadow = host.attachShadow({ mode: 'closed' });
    activeAutofillHost = host;

    const style = document.createElement('style');
    style.textContent = `
      * { margin: 0; padding: 0; box-sizing: border-box; }
      .zenith-dropdown {
        position: absolute;
        pointer-events: auto;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI Variable Text", "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
        background: #161a2e;
        color: #e9ebf8;
        border: 1px solid #262c47;
        border-radius: 12px;
        box-shadow: 0 12px 36px rgba(0, 0, 0, 0.45), 0 2px 6px rgba(0, 0, 0, 0.2);
        width: 320px;
        max-width: calc(100vw - 24px);
        overflow: hidden;
        animation: zenithFadeIn 0.16s cubic-bezier(0.16, 1, 0.3, 1);
        cursor: default;
        user-select: none;
      }
      @media (prefers-color-scheme: light) {
        .zenith-dropdown {
          background: #ffffff;
          color: #1c2036;
          border: 1px solid #e3e6f0;
          box-shadow: 0 12px 32px rgba(28, 32, 54, 0.14), 0 2px 6px rgba(28, 32, 54, 0.06);
        }
      }
      @keyframes zenithFadeIn {
        from { opacity: 0; transform: translateY(-4px); }
        to { opacity: 1; transform: translateY(0); }
      }
      .zenith-header {
        display: flex;
        align-items: center;
        gap: 7px;
        padding: 9px 12px 7px;
        font-size: 11px;
        font-weight: 600;
        letter-spacing: 0.02em;
        text-transform: uppercase;
        color: #4a63e6;
        border-bottom: 1px solid rgba(255, 255, 255, 0.06);
      }
      @media (prefers-color-scheme: light) {
        .zenith-header {
          color: #3b5bdb;
          border-bottom: 1px solid #eef0f8;
        }
      }
      .zenith-header img {
        width: 14px;
        height: 14px;
        border-radius: 3px;
        display: block;
        object-fit: cover;
      }
      .zenith-item {
        display: flex;
        align-items: center;
        gap: 10px;
        padding: 10px 12px;
        cursor: pointer;
        transition: background 0.12s ease;
      }
      .zenith-item:hover, .zenith-item.selected {
        background: rgba(59, 91, 219, 0.14);
      }
      @media (prefers-color-scheme: light) {
        .zenith-item:hover, .zenith-item.selected {
          background: rgba(59, 91, 219, 0.08);
        }
      }
      .zenith-icon {
        width: 28px;
        height: 28px;
        border-radius: 7px;
        overflow: hidden;
        display: flex;
        align-items: center;
        justify-content: center;
        flex-shrink: 0;
        box-shadow: 0 2px 6px rgba(0, 0, 0, 0.25);
      }
      .zenith-icon img {
        width: 100%;
        height: 100%;
        display: block;
        object-fit: cover;
      }
      .zenith-content {
        flex: 1;
        min-width: 0;
      }
      .zenith-username {
        font-size: 13.5px;
        font-weight: 600;
        line-height: 1.25;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
      }
      .zenith-subtitle {
        font-size: 11px;
        color: #9aa3c0;
        margin-top: 2px;
      }
      @media (prefers-color-scheme: light) {
        .zenith-subtitle {
          color: #5c6480;
        }
      }
      .zenith-footer {
        padding: 7px 12px;
        background: rgba(0, 0, 0, 0.16);
        border-top: 1px solid rgba(255, 255, 255, 0.06);
        font-size: 10px;
        color: #9aa3c0;
        text-align: center;
      }
      @media (prefers-color-scheme: light) {
        .zenith-footer {
          background: #f8f9fc;
          border-top: 1px solid #eef0f8;
          color: #5c6480;
        }
      }
    `;

    const dropdown = document.createElement('div');
    dropdown.className = 'zenith-dropdown';

    function updatePosition() {
      if (!inputElement || !inputElement.isConnected) {
        hideAutofillDropdown();
        return;
      }
      const rect = inputElement.getBoundingClientRect();
      const top = rect.bottom + window.scrollY + 6;
      const left = Math.max(8, Math.min(rect.left + window.scrollX, window.innerWidth - 336));
      dropdown.style.top = `${top}px`;
      dropdown.style.left = `${left}px`;
    }
    updatePosition();

    // Header
    const header = document.createElement('div');
    header.className = 'zenith-header';
    header.innerHTML = `
      <img src="${ZENITH_LOGO_DATA_URL}" alt="Zenith Passkeys" width="14" height="14">
      <span>Zenith Passkeys</span>
    `;
    dropdown.appendChild(header);

    // List of credentials
    let selectedIndex = 0;
    const itemEls = [];

    candidates.forEach((cand, idx) => {
      const item = document.createElement('div');
      item.className = 'zenith-item' + (idx === 0 ? ' selected' : '');
      item.innerHTML = `
        <div class="zenith-icon">
          <img src="${ZENITH_LOGO_DATA_URL}" alt="Zenith Passkeys" width="28" height="28">
        </div>
        <div class="zenith-content">
          <div class="zenith-username">${cand.username || 'Passkey User'}</div>
          <div class="zenith-subtitle">Passkey &bull; Zenith Passkeys</div>
        </div>
      `;

      item.addEventListener('mousedown', (e) => {
        e.preventDefault();
        hideAutofillDropdown();
        onSelect(cand, inputElement);
      });

      dropdown.appendChild(item);
      itemEls.push(item);
    });

    // Footer branding
    const footer = document.createElement('div');
    footer.className = 'zenith-footer';
    footer.textContent = 'Built and managed by Zenith Open Source Projects';
    dropdown.appendChild(footer);

    shadow.appendChild(style);
    shadow.appendChild(dropdown);
    document.documentElement.appendChild(host);

    window.addEventListener('scroll', updatePosition, { passive: true });
    window.addEventListener('resize', updatePosition, { passive: true });

    function onDocClick(e) {
      if (e.target !== inputElement) {
        hideAutofillDropdown();
        cleanupListeners();
      }
    }

    function onDocKeydown(e) {
      if (e.key === 'Escape') {
        hideAutofillDropdown();
        cleanupListeners();
      } else if (e.key === 'ArrowDown') {
        e.preventDefault();
        selectedIndex = (selectedIndex + 1) % candidates.length;
        itemEls.forEach((el, i) => el.classList.toggle('selected', i === selectedIndex));
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        selectedIndex = (selectedIndex - 1 + candidates.length) % candidates.length;
        itemEls.forEach((el, i) => el.classList.toggle('selected', i === selectedIndex));
      } else if (e.key === 'Enter' && activeAutofillHost) {
        e.preventDefault();
        hideAutofillDropdown();
        cleanupListeners();
        onSelect(candidates[selectedIndex], inputElement);
      }
    }

    function cleanupListeners() {
      document.removeEventListener('mousedown', onDocClick);
      document.removeEventListener('keydown', onDocKeydown);
      window.removeEventListener('scroll', updatePosition);
      window.removeEventListener('resize', updatePosition);
    }

    document.addEventListener('mousedown', onDocClick);
    document.addEventListener('keydown', onDocKeydown);
  }

  // ── Zenith get() handler ──────────────────────────────────────────
  async function zenithGet(options) {
    if (!options || !options.publicKey) {
      return originalGet ? originalGet(options) : Promise.reject(new DOMException('WebAuthn not supported', 'NotSupportedError'));
    }

    // Conditional UI (mediation: "conditional") for passkey autofill
    if (options.mediation === 'conditional') {
      const rpId = (options.publicKey && options.publicKey.rpId) || window.location.hostname;
      const candidates = await queryCandidates(rpId);

      // If no matching passkeys in Zenith, fall through to browser's native authenticator
      if (!candidates || candidates.length === 0) {
        return originalGet ? originalGet(options) : Promise.resolve(null);
      }

      return new Promise((resolve, reject) => {
        if (options.signal) {
          if (options.signal.aborted) {
            return reject(new DOMException('The operation was aborted.', 'AbortError'));
          }
          options.signal.addEventListener('abort', () => {
            hideAutofillDropdown();
            reject(new DOMException('The operation was aborted.', 'AbortError'));
          });
        }

        const onSelect = async (cand, inputEl) => {
          try {
            if (inputEl && cand.username) {
              inputEl.value = cand.username;
              inputEl.dispatchEvent(new Event('input', { bubbles: true }));
              inputEl.dispatchEvent(new Event('change', { bubbles: true }));
            }
            const serialized = serializePublicKey(options.publicKey);
            serialized.from_autofill = true;
            serialized.selectedCredentialId = cand.id;

            const result = await postAndWait('get', serialized, window.location.origin, options.signal);
            const cred = deserializeCredential(result.credential);
            resolve(cred);
          } catch (err) {
            reject(err);
          }
        };

        const attachToInput = (input) => {
          input.addEventListener('focus', () => renderAutofillDropdown(input, candidates, onSelect));
          input.addEventListener('click', () => renderAutofillDropdown(input, candidates, onSelect));
        };

        document.querySelectorAll('input').forEach((input) => {
          if (isCandidateInput(input)) attachToInput(input);
        });

        document.addEventListener('focusin', (e) => {
          if (isCandidateInput(e.target)) {
            renderAutofillDropdown(e.target, candidates, onSelect);
          }
        });

        if (document.activeElement && isCandidateInput(document.activeElement)) {
          renderAutofillDropdown(document.activeElement, candidates, onSelect);
        }
      });
    }

    if (options.signal && options.signal.aborted) {
      throw new DOMException('The operation was aborted.', 'AbortError');
    }

    const serialized = serializePublicKey(options.publicKey);
    const result = await postAndWait('get', serialized, window.location.origin, options.signal);
    return deserializeCredential(result.credential);
  }

  // ── Override navigator.credentials methods ────────────────────────
  function applyOverride(name, fn) {
    // Strategy 1: Override on CredentialsContainer.prototype (best — catches all instances)
    if (CredProto) {
      try {
        Object.defineProperty(CredProto, name, {
          value: fn,
          writable: true,
          configurable: true,
        });
      } catch (e) {
        try { CredProto[name] = fn; } catch (_) {}
      }
    }

    // Strategy 2: defineProperty on the navigator.credentials instance
    if (typeof navigator !== 'undefined' && navigator.credentials) {
      try {
        Object.defineProperty(navigator.credentials, name, {
          value: fn,
          writable: true,
          configurable: true,
        });
      } catch (e) {
        try { navigator.credentials[name] = fn; } catch (_) {}
      }
    }
  }

  applyOverride('create', zenithCreate);
  applyOverride('get', zenithGet);

  // Ensure platform authenticator availability reports true
  if (typeof PublicKeyCredential !== 'undefined') {
    try {
      PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable = async () => true;
    } catch (_) {}
    try {
      PublicKeyCredential.isConditionalMediationAvailable = async () => true;
    } catch (_) {}
  }
})();
