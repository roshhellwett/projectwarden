importScripts('lib/cbor.js', 'fallback-vault.js');

const SUPPORT_EMAIL = 'zenithprojects@icloud.com';

let nativePort = null;
let useFallback = false;
let pendingRequests = {};
let confirmWindows = {};
let rpIndex = {};

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
    if (!nativePort) {
      useFallback = true;
      return false;
    }

    nativePort.onMessage.addListener(handleNativeMessage);

    nativePort.onDisconnect.addListener(() => {
      nativePort = null;
      useFallback = true;
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
    const requestId = crypto.randomUUID();
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
      .catch(err => sendResponse({ error: err.message, support: SUPPORT_EMAIL }));
    return true;
  }

  // Query candidate credentials for conditional autofill dropdown
  if (action === 'webauthn_query_candidates') {
    handleQueryCandidates(msg, sender)
      .then(candidates => sendResponse({ candidates }))
      .catch(() => sendResponse({ candidates: [] }));
    return true;
  }

  // Status check: 'connected' means native host is reachable.
  // 'unlocked' is only reliably known from is_unlocked; report false here
  // so callers don't conflate "host is running" with "vault is open".
  if (action === 'get_status') {
    sendResponse({
      unlocked: false,  // callers should use 'is_unlocked' for real state
      fallback: useFallback,
      connected: nativePort !== null && !useFallback,
      support: SUPPORT_EMAIL,
    });
    return false;
  }

  // Confirmation response from confirm.html popup
  if (action === 'confirm_response') {
    const confId = msg.confirmId;
    if (confirmWindows[confId]) {
      confirmWindows[confId].resolve(msg.allowed);
      chrome.windows.remove(confirmWindows[confId].windowId);
      delete confirmWindows[confId];
    }
    return false;
  }

  if (action === 'open_dashboard') {
    const url = chrome.runtime.getURL('dashboard/dashboard.html');
    chrome.tabs.query({ url }, (tabs) => {
      if (tabs && tabs.length > 0) {
        chrome.tabs.update(tabs[0].id, { active: true });
        chrome.windows.update(tabs[0].windowId, { focused: true });
      } else {
        chrome.tabs.create({ url });
      }
      sendResponse({ success: true });
    });
    return true;
  }

  // Vault operations
  const vaultActions = [
    'vault_exists', 'is_unlocked', 'unlock', 'create_vault',
    'list_credentials', 'lock', 'get_settings', 'update_settings',
    'delete_credential', 'recover_vault',
    'change_password', 'get_audit_report', 'get_action_logs',
    'get_backup_blob', 'restore_backup_blob', 'export_vault', 'import_vault',
    'rotate_recovery_key',
  ];

  if (vaultActions.includes(action)) {
    if (useFallback) {
      handleFallbackAction(action, msg)
        .then(result => {
          if (action === 'unlock' && result && result.success) {
            ZenithFallback.listCredentials().then(creds => {
              rpIndex = {};
              for (const c of creds || []) {
                if (!rpIndex[c.rpId]) rpIndex[c.rpId] = [];
                rpIndex[c.rpId].push({ id: c.credentialId, username: c.username, rpId: c.rpId });
              }
            }).catch(() => {});
          } else if (action === 'lock') {
            rpIndex = {};
          }
          sendResponse(result);
        })
        .catch(e => sendResponse({ error: e.message, support: SUPPORT_EMAIL }));
    } else {
      sendToNative(action, msg)
        .then(result => {
          if (action === 'unlock' && result && result.success) {
            sendToNative('list_credentials', {}).then(listResp => {
              if (listResp && listResp.credentials) {
                rpIndex = {};
                for (const c of listResp.credentials) {
                  if (!rpIndex[c.rpId]) rpIndex[c.rpId] = [];
                  rpIndex[c.rpId].push({ id: c.credentialId, username: c.username, rpId: c.rpId });
                }
              }
            }).catch(() => {});
          } else if (action === 'lock') {
            rpIndex = {};
          }
          sendResponse(result);
        })
        .catch(err => sendResponse({ error: err.message, support: SUPPORT_EMAIL }));
    }
    return true;
  }
});

// ─── Fallback Action Handler ──────────────────────────────────────
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
    case 'recover_vault':
      if (ZenithFallback.recoverVault) {
        return ZenithFallback.recoverVault(msg.recoveryKey, msg.newPassword);
      }
      return { error: 'Recovery is not available in browser-only mode. Install the CLI: pip install -e ./cli, then run zenith-passkeys init --recover.', support: SUPPORT_EMAIL };
    case 'get_settings':
      return ZenithFallback.getSettings ? ZenithFallback.getSettings() : { settings: { idle_timeout_minutes: 15 } };
    case 'update_settings':
      return ZenithFallback.updateSettings ? ZenithFallback.updateSettings(msg.settings) : { success: true };
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
    case 'change_password':
      return ZenithFallback.changePassword(msg.oldPassword, msg.newPassword);
    case 'get_audit_report':
      return ZenithFallback.getAuditReport(msg.unusedDays);
    case 'get_action_logs':
      return ZenithFallback.getActionLogs();
    case 'get_backup_blob':
      return ZenithFallback.getBackupBlob();
    case 'restore_backup_blob':
      return ZenithFallback.restoreBackupBlob(msg.backupBlob, msg.password);
    case 'export_vault':
      return ZenithFallback.exportVault(msg.password);
    case 'rotate_recovery_key':
      if (ZenithFallback.rotateRecoveryKey) {
        const key = await ZenithFallback.rotateRecoveryKey();
        return { success: true, recovery_key: key };
      }
      return { error: 'Recovery rotation not supported in fallback mode' };
    case 'import_vault':
      return ZenithFallback.importVault(msg.credentials);
    default:
      return { error: 'Not supported in fallback mode' };
  }
}

// ─── Query Candidates for Conditional Autofill Dropdown ──────────
async function handleQueryCandidates(msg, sender) {
  let origin = '';
  try {
    origin = sender && sender.url ? new URL(sender.url).origin : (msg.origin || '');
  } catch (_) {
    origin = msg.origin || '';
  }
  let rpId = msg.rpId;
  if (!rpId && origin) {
    try { rpId = new URL(origin).hostname; } catch (_) {}
  }
  if (!rpId) return [];

  // 1. Fallback mode
  if (useFallback) {
    const creds = await ZenithFallback.listCredentials();
    return (creds || [])
      .filter(c => c.rpId === rpId || rpId.endsWith('.' + c.rpId))
      .map(c => ({ id: c.credentialId, username: c.username, rpId: c.rpId }));
  }

  // 2. In-memory cache check (domain & subdomain matches)
  const cachedMatches = [];
  for (const [cachedRpId, list] of Object.entries(rpIndex)) {
    if (cachedRpId === rpId || rpId.endsWith('.' + cachedRpId)) {
      cachedMatches.push(...list);
    }
  }
  if (cachedMatches.length > 0) {
    return cachedMatches;
  }

  // 3. Query native host
  try {
    ensureConnected();
    if (nativePort) {
      const resp = await sendToNative('list_credentials', { domain: rpId });
      if (resp && resp.credentials) {
        const matches = resp.credentials.map(c => ({
          id: c.credentialId,
          username: c.username,
          rpId: c.rpId,
        }));
        rpIndex[rpId] = matches;
        return matches;
      }
    }
  } catch (_) {}

  return rpIndex[rpId] || [];
}

// ─── WebAuthn Request Handler ────────────────────────────────────
async function handleWebAuthnRequest(msg, sender) {
  const action = msg.action === 'webauthn_create' ? 'create' : 'get';

  // SECURITY: trust ONLY the sender tab's URL; a message can claim any origin.
  let origin = '';
  try {
    origin = sender && sender.url ? new URL(sender.url).origin : '';
  } catch (e) {
    origin = '';
  }
  if (!origin) origin = msg.origin || '';
  if (!origin) throw new Error('Missing origin');

  // Direct 1-click login if triggered by autofill dropdown click while unlocked
  let allowed = false;
  if (msg.options && msg.options.from_autofill) {
    let isUnlocked = false;
    if (useFallback) {
      isUnlocked = ZenithFallback._isUnlocked ? ZenithFallback._isUnlocked() : false;
    } else {
      try {
        const st = await sendToNative('is_unlocked', {});
        isUnlocked = !!(st && st.unlocked);
      } catch (_) {}
    }

    if (isUnlocked) {
      allowed = true; // User intentionally clicked their passkey in the dropdown
    } else {
      allowed = await showConfirmation('verify', origin, msg.options);
    }
  } else {
    allowed = await showConfirmation(action, origin, msg.options);
  }

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

  let resp = await sendToNative(
    msg.action === 'webauthn_create' ? 'create_credential' : 'get_assertion',
    { options: msg.options, origin }
  );

  // The host refused to sign because the RP requires user verification
  // and our verification is stale. Re-verify with the master password,
  // then retry the assertion once.
  if (resp && resp.needs_verification) {
    const ok = await requestReverification(origin);
    if (!ok) throw new Error('User denied the request');
    resp = await sendToNative(
      msg.action === 'webauthn_create' ? 'create_credential' : 'get_assertion',
      { options: msg.options, origin }
    );
  }

  if (msg.action === 'webauthn_create' && resp && !resp.error) {
    rpIndex = {};
  }

  return resp;
}

// ─── Re-verification prompt (UV required + stale session) ────────
// Reuses the consent window with action='verify': the window ALWAYS asks
// for the master password (fresh verification), then resolves true.
async function requestReverification(origin) {
  return showConfirmation('verify', origin, null);
}

// ─── Confirmation Dialog ─────────────────────────────────────────
async function showConfirmation(action, origin, options) {
  return new Promise((resolve) => {
    const confirmId = crypto.randomUUID();
    confirmWindows[confirmId] = { resolve, action, origin, options };

    const width = 400;
    const height = 400;

    chrome.windows.create({
      url: chrome.runtime.getURL('confirm.html') + `?action=${action}&origin=${encodeURIComponent(origin)}&confirmId=${confirmId}`,
      type: 'popup',
      width,
      height,
    }, (window) => {
      if (window) {
        confirmWindows[confirmId].windowId = window.id;
      } else {
        // Window creation failed: auto-deny
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
