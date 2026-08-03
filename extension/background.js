importScripts('fallback-vault.js');

let nativePort = null;
let useFallback = false;
let pendingRequests = {};
let confirmWindows = {};

// ─── Window management for confirmation dialogs ──────────────────
chrome.windows.onRemoved.addListener((windowId) => {
  for (const [confId, conf] of Object.entries(confirmWindows)) {
    if (conf.windowId === windowId) {
      conf.resolve(false);
      delete confirmWindows[confId];
    }
  }
});

// ─── Native Host Connection ──────────────────────────────────────
function tryConnectNative() {
  try {
    nativePort = chrome.runtime.connectNative('com.zenith.passkeys');

    nativePort.onMessage.addListener(handleNativeMessage);

    nativePort.onDisconnect.addListener(() => {
      nativePort = null;
      if (chrome.runtime.lastError) {
        console.log('Native host disconnected:', chrome.runtime.lastError.message);
      }
      // Reject all pending requests
      for (const reqId in pendingRequests) {
        pendingRequests[reqId].reject(new Error('Native host disconnected'));
      }
      pendingRequests = {};
    });

    useFallback = false;
    return true;
  } catch (e) {
    console.warn('Native host not available, using fallback:', e);
    nativePort = null;
    useFallback = true;
    return false;
  }
}

function ensureConnected() {
  if (!nativePort && !useFallback) {
    tryConnectNative();
  }
}

function handleNativeMessage(msg) {
  const reqId = msg.requestId;
  if (reqId !== undefined && pendingRequests[reqId]) {
    pendingRequests[reqId].resolve(msg);
    delete pendingRequests[reqId];
  }
}

function sendToNative(action, data) {
  return new Promise((resolve, reject) => {
    const requestId = Date.now() + Math.random();
    pendingRequests[requestId] = { resolve, reject };
    const msg = { requestId, action, ...data };

    ensureConnected();

    if (nativePort) {
      try {
        nativePort.postMessage(msg);
      } catch (e) {
        delete pendingRequests[requestId];
        reject(new Error('Failed to send message to native host'));
        return;
      }
    } else {
      delete pendingRequests[requestId];
      reject(new Error('Native host not connected'));
      return;
    }

    // Timeout after 30 seconds
    setTimeout(() => {
      if (pendingRequests[requestId]) {
        const rej = pendingRequests[requestId].reject;
        delete pendingRequests[requestId];
        rej(new Error('Native host timeout'));
      }
    }, 30000);
  });
}

// Initial connection attempt
tryConnectNative();

// ─── Message Router ──────────────────────────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  const action = msg.action;

  // WebAuthn requests
  if (action === 'webauthn_create' || action === 'webauthn_get') {
    handleWebAuthnRequest(msg, sender)
      .then(result => sendResponse(result))
      .catch(err => sendResponse({ error: err.message }));
    return true;
  }

  // Status check
  if (action === 'get_status') {
    sendResponse({
      unlocked: nativePort !== null || useFallback,
      fallback: useFallback,
      connected: nativePort !== null,
    });
    return true;
  }

  // Confirmation response from confirm.html popup
  if (action === 'confirm_response') {
    const confId = msg.confirmId;
    if (confirmWindows[confId]) {
      confirmWindows[confId].resolve(msg.allowed);
      chrome.windows.remove(confirmWindows[confId].windowId);
      delete confirmWindows[confId];
    }
    return true;
  }

  // Vault operations
  const vaultActions = [
    'vault_exists', 'is_unlocked', 'unlock', 'create_vault',
    'list_credentials', 'lock', 'get_settings', 'update_settings',
    'delete_credential',
  ];

  if (vaultActions.includes(action)) {
    if (useFallback) {
      handleFallbackAction(action, msg)
        .then(result => sendResponse(result))
        .catch(e => sendResponse({ error: e.message }));
    } else {
      sendToNative(action, msg)
        .then(result => sendResponse(result))
        .catch(err => sendResponse({ error: err.message }));
    }
    return true;
  }
});

// ─── Fallback Action Handler ─────────────────────────────────────
async function handleFallbackAction(action, msg) {
  switch (action) {
    case 'vault_exists': {
      const data = await chrome.storage.local.get('zenith_vault');
      return { exists: !!data.zenith_vault };
    }
    case 'is_unlocked':
      return { unlocked: ZenithFallback._isUnlocked ? ZenithFallback._isUnlocked() : false };
    case 'create_vault': {
      const key = await ZenithFallback.createVault(msg.password);
      return { recovery_key: key };
    }
    case 'unlock': {
      const ok = await ZenithFallback.unlockVault(msg.password);
      return { success: ok };
    }
    case 'list_credentials': {
      const creds = await ZenithFallback.listCredentials();
      return { credentials: creds };
    }
    case 'lock':
      await ZenithFallback.lockVault();
      return { success: true };
    case 'delete_credential':
      if (ZenithFallback.deleteCredential) {
        await ZenithFallback.deleteCredential(msg.credentialId);
        return { success: true };
      }
      return { error: 'Delete not supported in fallback mode' };
    default:
      return { error: 'Not supported in fallback mode' };
  }
}

// ─── WebAuthn Request Handler ────────────────────────────────────
async function handleWebAuthnRequest(msg, sender) {
  const action = msg.action === 'webauthn_create' ? 'create' : 'get';
  const origin = msg.origin || (sender.url ? new URL(sender.url).origin : '');

  const allowed = await showConfirmation(action, origin, msg.options);
  if (!allowed) {
    throw new Error('User denied the request');
  }

  if (useFallback) {
    if (msg.action === 'webauthn_create') {
      return ZenithFallback.handleCreate(msg.options, origin);
    } else {
      return ZenithFallback.handleGet(msg.options, origin);
    }
  }

  return sendToNative(
    msg.action === 'webauthn_create' ? 'create_credential' : 'get_assertion',
    { options: msg.options, origin }
  );
}

// ─── Confirmation Dialog ─────────────────────────────────────────
async function showConfirmation(action, origin, options) {
  return new Promise((resolve) => {
    const confirmId = Date.now() + Math.random();
    confirmWindows[confirmId] = { resolve, action, origin, options };

    const width = 400;
    const height = 320;

    chrome.windows.create({
      url: chrome.runtime.getURL('confirm.html') + `?action=${action}&origin=${encodeURIComponent(origin)}&confirmId=${confirmId}`,
      type: 'popup',
      width,
      height,
    }, (window) => {
      if (window) {
        confirmWindows[confirmId].windowId = window.id;
      } else {
        // Window creation failed — auto-deny
        resolve(false);
        delete confirmWindows[confirmId];
      }
    });

    // Timeout after 2 minutes
    setTimeout(() => {
      if (confirmWindows[confirmId]) {
        confirmWindows[confirmId].resolve(false);
        delete confirmWindows[confirmId];
      }
    }, 120000);
  });
}
