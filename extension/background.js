importScripts('fallback-vault.js');

let nativePort = null;
let useFallback = false;
let pendingRequests = {};
let confirmWindows = {};

function tryConnectNative() {
  try {
    nativePort = chrome.runtime.connectNative('com.zenith.passkeys');
    nativePort.onMessage.addListener(handleNativeMessage);
    nativePort.onDisconnect.addListener(() => {
      nativePort = null;
      if (chrome.runtime.lastError) {
        console.log('Native host disconnected:', chrome.runtime.lastError.message);
      }
    });
    useFallback = false;
  } catch (e) {
    console.warn('Native host not available, using fallback:', e);
    useFallback = true;
  }
}

function handleNativeMessage(msg) {
  const reqId = msg.requestId;
  if (reqId !== undefined && pendingRequests[reqId]) {
    pendingRequests[reqId](msg);
    delete pendingRequests[reqId];
  }
}

function sendToNative(action, data) {
  return new Promise((resolve, reject) => {
    const requestId = Date.now() + Math.random();
    pendingRequests[requestId] = resolve;
    const msg = { requestId, action, ...data };
    if (nativePort) {
      nativePort.postMessage(msg);
    } else {
      reject(new Error('Native host not connected'));
    }
    setTimeout(() => {
      if (pendingRequests[requestId]) {
        delete pendingRequests[requestId];
        reject(new Error('Native host timeout'));
      }
    }, 30000);
  });
}

tryConnectNative();

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.action === 'webauthn_create' || msg.action === 'webauthn_get') {
    handleWebAuthnRequest(msg, sender)
      .then(result => sendResponse(result))
      .catch(err => sendResponse({ error: err.message }));
    return true;
  }
  if (msg.action === 'get_status') {
    sendResponse({ unlocked: nativePort !== null || useFallback, fallback: useFallback });
    return true;
  }
  if (msg.action === 'confirm_response') {
    const confId = msg.confirmId;
    if (confirmWindows[confId]) {
      confirmWindows[confId].resolve(msg.allowed);
      chrome.windows.remove(confirmWindows[confId].windowId);
      delete confirmWindows[confId];
    }
    return true;
  }
  if (['unlock', 'create_vault', 'list_credentials', 'lock', 'get_settings', 'update_settings'].includes(msg.action)) {
    if (useFallback) {
      if (msg.action === 'create_vault') ZenithFallback.createVault(msg.password).then(res => sendResponse({recovery_key: res})).catch(e => sendResponse({error: e.message}));
      else if (msg.action === 'unlock') ZenithFallback.unlockVault(msg.password).then(res => sendResponse({success: res})).catch(e => sendResponse({error: e.message}));
      else if (msg.action === 'list_credentials') ZenithFallback.listCredentials().then(res => sendResponse({credentials: res})).catch(e => sendResponse({error: e.message}));
      else if (msg.action === 'lock') ZenithFallback.lockVault().then(() => sendResponse({success: true})).catch(e => sendResponse({error: e.message}));
      else sendResponse({error: 'Not supported in fallback'});
    } else {
      sendToNative(msg.action, msg)
        .then(result => sendResponse(result))
        .catch(err => sendResponse({error: err.message}));
    }
    return true;
  }
});

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

  return sendToNative(msg.action === 'webauthn_create' ? 'create_credential' : 'get_assertion', {
    options: msg.options,
    origin,
  });
}

async function showConfirmation(action, origin, options) {
  return new Promise((resolve) => {
    const confirmId = Date.now() + Math.random();
    confirmWindows[confirmId] = { resolve, action, origin, options };

    const width = 400;
    const height = 300;

    chrome.windows.create({
      url: chrome.runtime.getURL('confirm.html') + `?action=${action}&origin=${encodeURIComponent(origin)}&confirmId=${confirmId}`,
      type: 'popup',
      width,
      height,

    }, (window) => {
      confirmWindows[confirmId].windowId = window.id;
    });

    setTimeout(() => {
      if (confirmWindows[confirmId]) {
        confirmWindows[confirmId].resolve(false);
        delete confirmWindows[confirmId];
      }
    }, 120000);
  });
}
