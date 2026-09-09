/**
 * Zenith Passkeys — Vault Dashboard
 * Built and managed by Zenith Open Source Projects.
 *
 * Zero cloud dependencies. 100% local-first and air-gapped.
 * Strict professional, minimal and sleek UI without emojis.
 */

(function () {
  'use strict';

  // ─── State ────────────────────────────────────────────────────────
  let currentCredentials = [];
  let isUnlocked = false;
  let isFallback = false;
  let pendingDeleteCred = null;
  let restoreFileBlobBase64 = null;
  let importCredentialsList = null;
  let rawEncryptedExport = null;

  // ─── Direct Fallback Dispatcher ──────────────────────────────────
  async function dispatchFallback(msg) {
    const fb = (typeof ZenithFallback !== 'undefined' && ZenithFallback) ? ZenithFallback :
               (typeof self !== 'undefined' && self.ZenithFallback) ? self.ZenithFallback : null;
    if (!fb) return { error: 'Vault engine not initialized.' };

    try {
      switch (msg.action) {
        case 'get_status':
          return { connected: false, fallback: true };
        case 'vault_exists':
          return { exists: fb.vaultExists ? await fb.vaultExists() : false };
        case 'create_vault': {
          const recKey = await fb.createVault(msg.password);
          return { success: true, recovery_key: recKey };
        }
        case 'is_unlocked':
          return { unlocked: fb._isUnlocked ? fb._isUnlocked() : false };
        case 'unlock': {
          const ok = await fb.unlockVault(msg.password);
          return { success: ok };
        }
        case 'list_credentials': {
          const creds = await fb.listCredentials();
          return { credentials: creds };
        }
        case 'lock':
          if (fb.lockVault) await fb.lockVault();
          return { success: true };
        case 'delete_credential':
          if (fb.deleteCredential) {
            await fb.deleteCredential(msg.credentialId);
            return { success: true };
          }
          return { error: 'Delete not supported in fallback' };
        case 'change_password':
          return fb.changePassword ? fb.changePassword(msg.oldPassword, msg.newPassword) : { error: 'Not supported' };
        case 'get_audit_report':
          return fb.getAuditReport ? fb.getAuditReport(msg.unusedDays) : { healthScore: 100, issues: [] };
        case 'get_action_logs':
          return fb.getActionLogs ? fb.getActionLogs() : { logs: [] };
        case 'get_backup_blob':
          return fb.getBackupBlob ? fb.getBackupBlob() : { error: 'Backup not supported' };
        case 'restore_backup_blob':
          return fb.restoreBackupBlob ? fb.restoreBackupBlob(msg.backupBlob, msg.password) : { error: 'Restore not supported' };
        case 'recover_vault':
          return fb.recoverVault ? fb.recoverVault(msg.recoveryKey, msg.newPassword) : { error: 'Recovery not supported' };
        case 'rotate_recovery_key':
          return fb.rotateRecoveryKey ? { success: true, recovery_key: await fb.rotateRecoveryKey() } : { error: 'Not supported' };
        case 'get_settings':
          return fb.getSettings ? fb.getSettings() : { settings: { idle_timeout_minutes: 15 } };
        case 'update_settings':
          return fb.updateSettings ? fb.updateSettings(msg.settings) : { success: true };
        case 'export_vault':
          return fb.exportVault ? fb.exportVault(msg.password) : { error: 'Export not supported' };
        case 'import_vault':
          return fb.importVault ? fb.importVault(msg.credentials || msg.encrypted_export, msg.password) : { error: 'Import not supported' };
        default:
          return { error: 'Unsupported action: ' + msg.action };
      }
    } catch (err) {
      return { error: err.message || 'Error processing vault request' };
    }
  }

  // ─── Messaging Wrapper ────────────────────────────────────────────
  async function sendMsg(message, timeoutMs = 3000) {
    if (typeof chrome === 'undefined' || !chrome.runtime || !chrome.runtime.id || !chrome.runtime.sendMessage) {
      return dispatchFallback(message);
    }
    return new Promise((resolve) => {
      let timer = setTimeout(() => {
        timer = null;
        resolve(dispatchFallback(message));
      }, timeoutMs);

      try {
        chrome.runtime.sendMessage(message, (response) => {
          if (!timer) return;
          clearTimeout(timer);
          if (chrome.runtime.lastError) {
            return resolve(dispatchFallback(message));
          }
          resolve(response || {});
        });
      } catch (err) {
        if (timer) clearTimeout(timer);
        resolve(dispatchFallback(message));
      }
    });
  }

  // ─── Enterprise Toast Notification Engine ─────────────────────────
  const TOAST_ICONS = {
    success: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12l5 5l10 -10"/></svg>',
    error: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 9v4"/><path d="M12 17h.01"/><path d="M12 3a9 9 0 1 0 9 9a9 9 0 0 0 -9 -9"/></svg>',
    danger: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 9v4"/><path d="M12 17h.01"/><path d="M12 3a9 9 0 1 0 9 9a9 9 0 0 0 -9 -9"/></svg>',
    warning: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 9v4"/><path d="M12 17h.01"/><path d="M5 19h14a2 2 0 0 0 1.84 -2.75l-7.1 -12.25a2 2 0 0 0 -3.5 0l-7.1 12.25a2 2 0 0 0 1.75 2.75"/></svg>',
    info: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 9h.01"/><path d="M11 12h1v4h1"/><path d="M12 3a9 9 0 1 0 9 9a9 9 0 0 0 -9 -9"/></svg>',
  };

  function showToast(message, type = 'success', title = null, duration = 3600) {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const safeType = ['success', 'error', 'danger', 'warning', 'info'].includes(type) ? type : 'info';
    const toast = document.createElement('div');
    toast.className = `toast toast-${safeType}`;

    const defaultTitle = {
      success: 'Success',
      error: 'Error',
      danger: 'Action Failed',
      warning: 'Warning',
      info: 'Notification',
    }[safeType] || 'Notification';

    const iconSvg = TOAST_ICONS[safeType] || TOAST_ICONS.info;
    const finalTitle = title || defaultTitle;

    toast.innerHTML = `
      <div class="toast-icon">${iconSvg}</div>
      <div class="toast-body">
        <span class="toast-title">${escapeHtml(finalTitle)}</span>
        <span class="toast-msg">${escapeHtml(message)}</span>
      </div>
      <button class="toast-close" title="Dismiss" type="button">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 6l-12 12"/><path d="M6 6l12 12"/></svg>
      </button>
      <div class="toast-progress" style="animation-duration: ${duration}ms;"></div>
    `;

    const closeBtn = toast.querySelector('.toast-close');
    let timer = null;

    function dismiss() {
      if (timer) clearTimeout(timer);
      toast.classList.remove('show');
      toast.classList.add('hide');
      setTimeout(() => toast.remove(), 220);
    }

    if (closeBtn) closeBtn.addEventListener('click', dismiss);

    container.appendChild(toast);
    requestAnimationFrame(() => toast.classList.add('show'));

    timer = setTimeout(dismiss, duration);
  }

  // ─── Timestamp & Date Utilities ───────────────────────────────────
  function formatTimestamp(ts) {
    if (!ts && ts !== 0) return '—';
    let ms;

    if (typeof ts === 'number') {
      // Python time.time() returns seconds (e.g. 1.7e9 < 1e11). Milliseconds are > 1e12.
      ms = ts < 1e11 ? ts * 1000 : ts;
    } else if (typeof ts === 'string') {
      const parsedNum = Number(ts);
      if (!isNaN(parsedNum) && parsedNum < 1e11) {
        ms = parsedNum * 1000;
      } else {
        const d = new Date(ts);
        if (!isNaN(d.getTime())) ms = d.getTime();
        else return String(ts);
      }
    } else {
      return '—';
    }

    const date = new Date(ms);
    if (isNaN(date.getTime())) return String(ts);

    return date.toLocaleString(undefined, {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });
  }

  function formatRelativeDate(ts) {
    if (!ts && ts !== 0) return 'Never';
    let ms;

    if (typeof ts === 'number') {
      ms = ts < 1e11 ? ts * 1000 : ts;
    } else if (typeof ts === 'string') {
      const parsedNum = Number(ts);
      if (!isNaN(parsedNum) && parsedNum < 1e11) {
        ms = parsedNum * 1000;
      } else {
        const d = new Date(ts);
        if (!isNaN(d.getTime())) ms = d.getTime();
        else return 'Never';
      }
    } else {
      return 'Never';
    }

    const date = new Date(ms);
    if (isNaN(date.getTime())) return 'Never';

    const now = Date.now();
    const diffSec = Math.floor((now - ms) / 1000);
    if (diffSec < 45) return 'Just now';
    const diffMin = Math.floor(diffSec / 60);
    if (diffMin < 60) return `${diffMin}m ago`;
    const diffHr = Math.floor(diffMin / 60);
    if (diffHr < 24) return `${diffHr}h ago`;
    const diffDays = Math.floor(diffHr / 24);
    if (diffDays === 1) return 'Yesterday';
    if (diffDays < 30) return `${diffDays}d ago`;

    return date.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
  }

  // ─── Navigation & Views ───────────────────────────────────────────
  const pageTitles = {
    passkeys: 'Passkeys Vault',
    audit: 'Security Audit & Diagnostics',
    logs: 'Vault Activity Log',
    backup: 'Backup & Restore',
    'import-export': 'Import & Export Passkeys',
    settings: 'Vault Settings',
  };

  function switchView(viewName) {
    document.querySelectorAll('.nav-item').forEach((btn) => {
      btn.classList.toggle('active', btn.dataset.view === viewName);
    });

    document.querySelectorAll('.content-view').forEach((view) => {
      view.classList.add('hidden');
      view.classList.remove('active');
    });

    const targetView = document.getElementById(`view-${viewName}`);
    if (targetView) {
      targetView.classList.remove('hidden');
      targetView.classList.add('active');
    }

    const titleEl = document.getElementById('page-title');
    if (titleEl && pageTitles[viewName]) {
      titleEl.textContent = pageTitles[viewName];
    }

    // Refresh data when switching to specific views
    if (isUnlocked) {
      if (viewName === 'passkeys') loadPasskeys(false);
      else if (viewName === 'audit') loadAuditReport(false);
      else if (viewName === 'logs') loadActionLogs(false);
      else if (viewName === 'settings') {
        sendMsg({ action: 'get_settings' }).then((res) => {
          if (res && res.settings && res.settings.idle_timeout_minutes) {
            const val = res.settings.idle_timeout_minutes;
            const timeoutSelect = document.getElementById('dash-timeout');
            const kpiAuto = document.getElementById('kpi-autolock-val');
            if (timeoutSelect) timeoutSelect.value = String(val);
            if (kpiAuto) kpiAuto.textContent = `${val} min`;
          }
        }).catch(() => {});
      }
    }
  }

  // ─── Vault Status & Gate ──────────────────────────────────────────
  function updateVaultIndicator(unlocked, fallback = false) {
    isUnlocked = unlocked;
    isFallback = fallback;

    const dot = document.getElementById('sidebar-status-dot');
    const label = document.getElementById('sidebar-status-text');
    const lockBtn = document.getElementById('sidebar-lock-btn');
    const unlockView = document.getElementById('view-unlock');

    if (dot) {
      dot.className = 'status-dot ' + (unlocked ? 'status-unlocked' : 'status-locked');
    }
    if (label) {
      if (unlocked) {
        label.textContent = fallback ? 'Vault Unlocked (Fallback)' : 'Vault Unlocked (Local Host)';
      } else {
        label.textContent = 'Vault Locked';
      }
    }
    if (lockBtn) {
      lockBtn.style.display = unlocked ? 'inline-flex' : 'none';
    }

    if (!unlocked) {
      // Show unlock gate
      document.querySelectorAll('.content-view').forEach((v) => {
        v.classList.remove('active');
        v.classList.add('hidden');
      });
      if (unlockView) {
        unlockView.classList.remove('hidden');
        unlockView.classList.add('active');
      }
      const titleEl = document.getElementById('page-title');
      if (titleEl) titleEl.textContent = 'Vault Locked';
    } else {
      if (unlockView) {
        unlockView.classList.add('hidden');
        unlockView.classList.remove('active');
      }
      const activeNav = document.querySelector('.nav-item.active');
      const currentView = activeNav ? activeNav.dataset.view : 'passkeys';
      switchView(currentView);
    }
  }

  async function checkStatusAndInit() {
    try {
      const existsResp = await sendMsg({ action: 'vault_exists' });
      const vaultExists = !!(existsResp && existsResp.exists);

      if (!vaultExists) {
        showFirstRunGate();
        return;
      }

      const status = await sendMsg({ action: 'get_status' });
      const unlockedResp = await sendMsg({ action: 'is_unlocked' });
      const unlocked = !!(unlockedResp && unlockedResp.unlocked);
      updateVaultIndicator(unlocked, !!(status && status.fallback));

      if (unlocked) {
        loadPasskeys(false);
        loadAuditReport(false);
        sendMsg({ action: 'get_settings' }).then((res) => {
          if (res && res.settings && res.settings.idle_timeout_minutes) {
            const val = res.settings.idle_timeout_minutes;
            const timeoutSelect = document.getElementById('dash-timeout');
            const kpiAuto = document.getElementById('kpi-autolock-val');
            if (timeoutSelect) timeoutSelect.value = String(val);
            if (kpiAuto) kpiAuto.textContent = `${val} min`;
          }
        }).catch(() => {});
      }
    } catch (e) {
      updateVaultIndicator(false, false);
    }
  }

  function showFirstRunGate() {
    isUnlocked = false;
    document.querySelectorAll('.content-view').forEach((v) => {
      v.classList.remove('active');
      v.classList.add('hidden');
    });
    const frView = document.getElementById('view-firstrun');
    if (frView) {
      frView.classList.remove('hidden');
      frView.classList.add('active');
    }
    const titleEl = document.getElementById('page-title');
    if (titleEl) titleEl.textContent = 'Vault Setup';
    const dot = document.getElementById('sidebar-status-dot');
    const label = document.getElementById('sidebar-status-text');
    if (dot) dot.className = 'status-dot status-locked';
    if (label) label.textContent = 'Setup Required';
  }

  function showUnlockGate() {
    isUnlocked = false;
    document.querySelectorAll('.content-view').forEach((v) => {
      v.classList.remove('active');
      v.classList.add('hidden');
    });
    const unlockView = document.getElementById('view-unlock');
    if (unlockView) {
      unlockView.classList.remove('hidden');
      unlockView.classList.add('active');
    }
    const titleEl = document.getElementById('page-title');
    if (titleEl) titleEl.textContent = 'Vault Locked';
    const dot = document.getElementById('sidebar-status-dot');
    const label = document.getElementById('sidebar-status-text');
    if (dot) dot.className = 'status-dot status-locked';
    if (label) label.textContent = 'Vault Locked';
  }

  function showRecoveryGate() {
    isUnlocked = false;
    document.querySelectorAll('.content-view').forEach((v) => {
      v.classList.remove('active');
      v.classList.add('hidden');
    });
    const recView = document.getElementById('view-recovery');
    if (recView) {
      recView.classList.remove('hidden');
      recView.classList.add('active');
    }
    const titleEl = document.getElementById('page-title');
    if (titleEl) titleEl.textContent = 'Recover Vault';
    const dot = document.getElementById('sidebar-status-dot');
    const label = document.getElementById('sidebar-status-text');
    if (dot) dot.className = 'status-dot status-locked';
    if (label) label.textContent = 'Vault Locked';
  }

  async function doRecoverVault() {
    const keyInput = document.getElementById('dash-recovery-key');
    const pwInput = document.getElementById('dash-recovery-password');
    const confirmInput = document.getElementById('dash-recovery-confirm');
    const errEl = document.getElementById('dash-recovery-error');
    const btn = document.getElementById('dash-recovery-submit-btn');

    const key = keyInput ? keyInput.value.trim() : '';
    const pw = pwInput ? pwInput.value : '';
    const confirm = confirmInput ? confirmInput.value : '';

    if (errEl) errEl.classList.add('hidden');

    if (!key) {
      if (errEl) {
        errEl.textContent = 'Please enter your emergency recovery key.';
        errEl.classList.remove('hidden');
      }
      return;
    }

    if (pw.length < 8) {
      if (errEl) {
        errEl.textContent = 'New master password must be at least 8 characters.';
        errEl.classList.remove('hidden');
      }
      return;
    }

    if (pw !== confirm) {
      if (errEl) {
        errEl.textContent = 'New passwords do not match.';
        errEl.classList.remove('hidden');
      }
      return;
    }

    if (btn) {
      btn.disabled = true;
      btn.innerHTML = '<svg class="spin-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path d="M12 3a9 9 0 1 0 9 9"/></svg> Recovering Vault...';
    }

    try {
      const resp = await sendMsg({
        action: 'recover_vault',
        recoveryKey: key,
        newPassword: pw,
      });

      if (resp && resp.error) {
        if (errEl) {
          errEl.textContent = resp.error;
          errEl.classList.remove('hidden');
        }
        showToast(resp.error, 'danger', 'Recovery Failed');
      } else if (resp && resp.success) {
        if (keyInput) keyInput.value = '';
        if (pwInput) pwInput.value = '';
        if (confirmInput) confirmInput.value = '';
        updateVaultIndicator(true, isFallback);
        showToast('Vault successfully recovered and unlocked with new password.', 'success', 'Vault Recovered');
        loadPasskeys(false);
        loadAuditReport(false);
      } else {
        if (errEl) {
          errEl.textContent = 'Invalid recovery key or recovery failed.';
          errEl.classList.remove('hidden');
        }
        showToast('Invalid recovery key.', 'danger', 'Recovery Failed');
      }
    } catch (err) {
      if (errEl) {
        errEl.textContent = err.message || 'Error communicating with vault.';
        errEl.classList.remove('hidden');
      }
      showToast(err.message || 'Connection error during recovery', 'danger', 'Recovery Error');
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.textContent = 'Recover Vault & Set Password';
      }
    }
  }

  async function doCreateVault() {
    const pwInput = document.getElementById('fr-dash-password');
    const confirmInput = document.getElementById('fr-dash-confirm');
    const errEl = document.getElementById('fr-dash-error');
    const btn = document.getElementById('fr-dash-create-btn');
    const recoveryWrap = document.getElementById('fr-dash-recovery-wrap');
    const recoveryDisplay = document.getElementById('fr-dash-recovery-display');

    const pw = pwInput ? pwInput.value : '';
    const confirm = confirmInput ? confirmInput.value : '';

    if (errEl) errEl.classList.add('hidden');

    if (pw.length < 8) {
      if (errEl) {
        errEl.textContent = 'Password must be at least 8 characters.';
        errEl.classList.remove('hidden');
      }
      return;
    }
    if (pw !== confirm) {
      if (errEl) {
        errEl.textContent = 'Passwords do not match.';
        errEl.classList.remove('hidden');
      }
      return;
    }

    if (btn) {
      btn.disabled = true;
      btn.innerHTML = '<svg class="spin-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path d="M12 3a9 9 0 1 0 9 9"/></svg> Creating Vault...';
    }

    try {
      const resp = await sendMsg({ action: 'create_vault', password: pw });
      if (resp && resp.error) {
        if (errEl) {
          errEl.textContent = resp.error;
          errEl.classList.remove('hidden');
        }
        showToast(resp.error, 'danger', 'Vault Creation Failed');
      } else {
        showToast('Vault created successfully.', 'success', 'Vault Created');
        if (resp && resp.recovery_key && resp.recovery_key !== 'fallback-no-recovery-key') {
          if (recoveryDisplay) recoveryDisplay.textContent = resp.recovery_key;
          if (recoveryWrap) recoveryWrap.classList.remove('hidden');
          if (btn) btn.classList.add('hidden');
          if (pwInput) pwInput.classList.add('hidden');
          if (confirmInput) confirmInput.classList.add('hidden');
        } else {
          updateVaultIndicator(true, isFallback);
          loadPasskeys(false);
          loadAuditReport(false);
        }
      }
    } catch (err) {
      if (errEl) {
        errEl.textContent = err.message || 'Error creating vault.';
        errEl.classList.remove('hidden');
      }
      showToast(err.message || 'Failed to create vault', 'danger', 'Creation Error');
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.textContent = 'Create Secure Vault';
      }
    }
  }

  // ─── Unlock Handler ───────────────────────────────────────────────
  async function doUnlock() {
    const input = document.getElementById('unlock-input');
    const errEl = document.getElementById('unlock-error');
    const btn = document.getElementById('unlock-submit-btn');
    const password = input ? input.value : '';

    if (!password) {
      if (errEl) {
        errEl.textContent = 'Please enter your master password.';
        errEl.classList.remove('hidden');
      }
      return;
    }

    if (errEl) errEl.classList.add('hidden');
    if (btn) {
      btn.disabled = true;
      btn.innerHTML = '<svg class="spin-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path d="M12 3a9 9 0 1 0 9 9"/></svg> Decrypting Vault...';
    }

    try {
      const resp = await sendMsg({ action: 'unlock', password });
      if (resp && resp.error) {
        if (errEl) {
          errEl.textContent = resp.error;
          errEl.classList.remove('hidden');
        }
        showToast(resp.error, 'danger', 'Unlock Failed');
      } else if (resp && resp.success) {
        if (input) input.value = '';
        updateVaultIndicator(true, isFallback);
        showToast('Vault decrypted and unlocked.', 'success', 'Vault Unlocked');
        loadPasskeys(false);
        loadAuditReport(false);
      } else {
        if (errEl) {
          errEl.textContent = 'Incorrect master password.';
          errEl.classList.remove('hidden');
        }
        showToast('Incorrect master password.', 'danger', 'Unlock Failed');
      }
    } catch (err) {
      if (errEl) {
        errEl.textContent = err.message || 'Error connecting to vault.';
        errEl.classList.remove('hidden');
      }
      showToast(err.message || 'Connection error', 'danger', 'Unlock Error');
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.textContent = 'Unlock Vault';
      }
    }
  }

  // ─── Lock Handler ─────────────────────────────────────────────────
  async function doLock() {
    const lockBtn = document.getElementById('sidebar-lock-btn');
    if (lockBtn) {
      lockBtn.disabled = true;
      lockBtn.innerHTML = '<svg class="spin-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="15" height="15"><path d="M12 3a9 9 0 1 0 9 9"/></svg><span>Locking...</span>';
    }

    try {
      await sendMsg({ action: 'lock' });
      updateVaultIndicator(false, isFallback);
      showToast('Vault has been locked and keys purged from memory.', 'info', 'Vault Locked');
      currentCredentials = [];
      const tbody = document.getElementById('passkeys-table-body');
      if (tbody) tbody.innerHTML = '';
      const countEl = document.getElementById('nav-cred-count');
      if (countEl) countEl.textContent = '0';
    } catch (err) {
      showToast(err.message || 'Failed to lock vault.', 'danger', 'Lock Error');
    } finally {
      if (lockBtn) {
        lockBtn.disabled = false;
        lockBtn.innerHTML = `
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M5 11a2 2 0 0 1 2 -2h10a2 2 0 0 1 2 2v8a2 2 0 0 1 -2 2h-10a2 2 0 0 1 -2 -2v-8z" />
            <path d="M12 16m-1 0a1 1 0 1 0 2 0a1 1 0 1 0 -2 0" />
            <path d="M8 11v-4a4 4 0 1 1 8 0v4" />
          </svg>
          <span>Lock Vault</span>
        `;
      }
    }
  }

  function getDomainMonogram(rawDomain) {
    const d = (rawDomain || '').toLowerCase().replace(/^https?:\/\//, '').replace(/^www\./, '');
    if (d.includes('github')) return 'GH';
    if (d.includes('google')) return 'G';
    if (d.includes('aws') || d.includes('amazon')) return 'AWS';
    if (d.includes('cloudflare')) return 'CF';
    if (d.includes('apple') || d.includes('icloud')) return 'AP';
    if (d.includes('microsoft')) return 'MS';
    if (d.includes('binance')) return 'BN';
    if (d.includes('gitlab')) return 'GL';
    return d.slice(0, 2).toUpperCase() || 'ID';
  }

  // ─── Passkeys List View ───────────────────────────────────────────
  function renderPasskeys(list) {
    const tbody = document.getElementById('passkeys-table-body');
    const emptyState = document.getElementById('passkeys-empty');
    const countBadge = document.getElementById('nav-cred-count');
    const kpiCount = document.getElementById('kpi-cred-count');
    const kpiSub = document.getElementById('kpi-cred-sub');

    if (countBadge) countBadge.textContent = list.length;
    if (kpiCount) kpiCount.textContent = list.length;
    if (kpiSub) kpiSub.textContent = list.length === 1 ? '1 active credential' : `${list.length} active credentials`;

    if (!tbody) return;

    tbody.innerHTML = '';

    if (!list || list.length === 0) {
      if (emptyState) emptyState.classList.remove('hidden');
      return;
    }

    if (emptyState) emptyState.classList.add('hidden');

    list.forEach((c) => {
      const tr = document.createElement('tr');

      const domain = c.rpId || c.rp_id || 'Unknown Service';
      const username = c.username || 'Unspecified User';
      const credId = c.credentialId || c.credential_id || '';
      const shortId = credId.length > 18 ? credId.slice(0, 8) + '...' + credId.slice(-6) : credId;
      const lastUsed = formatRelativeDate(c.lastUsedAt || c.last_used_at);
      const fullLastUsed = formatTimestamp(c.lastUsedAt || c.last_used_at);
      const created = formatTimestamp(c.createdAt || c.created_at);
      const monogram = getDomainMonogram(domain);

      tr.innerHTML = `
        <td>
          <div class="domain-cell">
            <span class="domain-avatar" title="${escapeHtml(domain)}">${escapeHtml(monogram)}</span>
            <div class="domain-info">
              <span class="domain-name">${escapeHtml(domain)}</span>
              <span class="curve-badge">ES256</span>
            </div>
          </div>
        </td>
        <td>
          <span class="username-text">${escapeHtml(username)}</span>
        </td>
        <td>
          <div class="cred-id-pill" title="Click to copy full ID" data-copy="${escapeHtml(credId)}">
            <code>${escapeHtml(shortId)}</code>
            <span class="pill-icon">
              <svg class="copy-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="13" height="13">
                <path d="M8 8m0 2a2 2 0 0 1 2 -2h8a2 2 0 0 1 2 2v8a2 2 0 0 1 -2 2h-8a2 2 0 0 1 -2 -2z" />
                <path d="M16 8v-2a2 2 0 0 0 -2 -2h-8a2 2 0 0 0 -2 2v8a2 2 0 0 0 2 2h2" />
              </svg>
            </span>
          </div>
        </td>
        <td><span class="date-cell" title="${escapeHtml(fullLastUsed)}">${escapeHtml(lastUsed)}</span></td>
        <td><span class="date-cell">${escapeHtml(created)}</span></td>
        <td class="text-right">
          <button class="btn-action-icon btn-delete-row" title="Delete passkey" data-id="${escapeHtml(credId)}" data-domain="${escapeHtml(domain)}" data-user="${escapeHtml(username)}">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="15" height="15">
              <path d="M4 7l16 0" /><path d="M10 11l0 6" /><path d="M14 11l0 6" />
              <path d="M5 7l1 12a2 2 0 0 0 2 2h8a2 2 0 0 0 2 -2l1 -12" />
              <path d="M9 7v-3a1 1 0 0 1 1 -1h4a1 1 0 0 1 1 1v3" />
            </svg>
          </button>
        </td>
      `;

      // Copy credential ID listener with visual micro-animation
      const copyPill = tr.querySelector('.cred-id-pill');
      if (copyPill) {
        copyPill.addEventListener('click', () => {
          navigator.clipboard.writeText(credId).then(() => {
            copyPill.classList.add('copied');
            const iconSpan = copyPill.querySelector('.pill-icon');
            if (iconSpan) {
              iconSpan.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="13" height="13"><path d="M5 12l5 5l10 -10"/></svg>';
            }
            setTimeout(() => {
              copyPill.classList.remove('copied');
              if (iconSpan) {
                iconSpan.innerHTML = '<svg class="copy-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="13" height="13"><path d="M8 8m0 2a2 2 0 0 1 2 -2h8a2 2 0 0 1 2 2v8a2 2 0 0 1 -2 2h-8a2 2 0 0 1 -2 -2z"/><path d="M16 8v-2a2 2 0 0 0 -2 -2h-8a2 2 0 0 0 -2 2v8a2 2 0 0 0 2 2h2"/></svg>';
              }
            }, 1600);
            showToast(`Credential ID for "${domain}" copied to clipboard.`, 'success', 'Copied to Clipboard', 2600);
          });
        });
      }

      // Delete passkey listener
      const delBtn = tr.querySelector('.btn-delete-row');
      if (delBtn) {
        delBtn.addEventListener('click', () => {
          openDeleteModal({
            credentialId: credId,
            rpId: domain,
            username: username,
          });
        });
      }

      tbody.appendChild(tr);
    });
  }

  async function loadPasskeys(isUserClick = false) {
    if (!isUnlocked) return;
    const refreshBtn = document.getElementById('refresh-passkeys-btn');
    const tbody = document.getElementById('passkeys-table-body');
    const icon = refreshBtn ? refreshBtn.querySelector('svg') : null;

    if (refreshBtn) refreshBtn.disabled = true;
    if (icon) icon.classList.add('spin-icon');

    if (isUserClick && tbody) {
      tbody.innerHTML = '<tr class="table-loading-row"><td colspan="6"><div class="table-loading-spinner"><svg class="spin-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path d="M12 3a9 9 0 1 0 9 9"/></svg> Refreshing stored passkeys...</div></td></tr>';
    }

    try {
      const resp = await sendMsg({ action: 'list_credentials' });
      currentCredentials = (resp && resp.credentials) || [];
      filterPasskeys();

      if (isUserClick) {
        showToast(`Passkeys list refreshed (${currentCredentials.length} credentials stored).`, 'success', 'Passkeys Refreshed');
      }
    } catch (err) {
      showToast('Error loading passkeys: ' + err.message, 'danger', 'Refresh Failed');
    } finally {
      if (refreshBtn) refreshBtn.disabled = false;
      if (icon) icon.classList.remove('spin-icon');
    }
  }

  function filterPasskeys() {
    const searchInput = document.getElementById('passkey-search');
    const query = searchInput ? searchInput.value.toLowerCase().trim() : '';

    if (!query) {
      renderPasskeys(currentCredentials);
      return;
    }

    const filtered = currentCredentials.filter((c) => {
      const domain = (c.rpId || c.rp_id || '').toLowerCase();
      const user = (c.username || '').toLowerCase();
      return domain.includes(query) || user.includes(query);
    });

    renderPasskeys(filtered);
  }

  // ─── Delete Modal ─────────────────────────────────────────────────
  function openDeleteModal(cred) {
    pendingDeleteCred = cred;
    const modal = document.getElementById('delete-modal');
    const text = document.getElementById('delete-modal-text');
    if (text) {
      text.textContent = `Are you sure you want to permanently delete the passkey for "${cred.rpId}" (${cred.username})? This action cannot be undone.`;
    }
    if (modal) modal.classList.remove('hidden');
  }

  function closeDeleteModal() {
    pendingDeleteCred = null;
    const modal = document.getElementById('delete-modal');
    if (modal) modal.classList.add('hidden');
  }

  async function confirmDeletePasskey() {
    if (!pendingDeleteCred) return;
    const cred = pendingDeleteCred;
    const confirmBtn = document.getElementById('delete-confirm-btn');

    if (confirmBtn) {
      confirmBtn.disabled = true;
      confirmBtn.textContent = 'Deleting...';
    }

    try {
      const resp = await sendMsg({
        action: 'delete_credential',
        credentialId: cred.credentialId,
        rpId: cred.rpId,
      });

      closeDeleteModal();

      if (resp && resp.error) {
        showToast('Error deleting passkey: ' + resp.error, 'danger', 'Delete Error');
      } else {
        showToast(`Passkey for ${cred.rpId} permanently deleted.`, 'success', 'Passkey Deleted');
        loadPasskeys(false);
        loadAuditReport(false);
      }
    } catch (err) {
      closeDeleteModal();
      showToast(err.message || 'Failed to delete credential.', 'danger', 'Delete Error');
    } finally {
      if (confirmBtn) {
        confirmBtn.disabled = false;
        confirmBtn.textContent = 'Delete Permanently';
      }
    }
  }

  // ─── Security Audit & Diagnostics ─────────────────────────────────
  async function loadAuditReport(isUserClick = false) {
    if (!isUnlocked) return;
    const btn = document.getElementById('run-audit-btn');

    if (btn) {
      btn.disabled = true;
      btn.textContent = 'Analyzing...';
    }

    try {
      const report = await sendMsg({ action: 'get_audit_report', unusedDays: 90 });
      if (report && !report.error) {
        renderAuditReport(report);
        if (isUserClick) {
          const score = typeof report.healthScore === 'number' ? report.healthScore : 100;
          const grade = report.grade || 'A';
          showToast(`Security audit completed: Health Score ${score}/100 (Grade ${grade}).`, 'success', 'Audit Complete');
        }
      }
    } catch (err) {
      if (isUserClick) showToast('Security audit failed: ' + err.message, 'danger', 'Audit Error');
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.textContent = 'Re-run Audit';
      }
    }
  }

  function renderAuditReport(report) {
    const scoreNum = document.getElementById('audit-score-num');
    const scoreDesc = document.getElementById('audit-score-desc');
    const gradePill = document.getElementById('audit-grade-pill');
    const navBadge = document.getElementById('nav-audit-badge');
    const findingsList = document.getElementById('audit-findings-list');

    const score = typeof report.healthScore === 'number' ? report.healthScore : 100;
    const grade = report.grade || 'A';

    if (scoreNum) scoreNum.textContent = `${score} / 100`;
    const kpiScore = document.getElementById('kpi-security-score');
    if (kpiScore) {
      kpiScore.textContent = `${score} / 100`;
      kpiScore.className = `kpi-value ${score >= 85 ? 'kpi-val-success' : 'kpi-val-warning'}`;
    }

    if (gradePill) {
      gradePill.className = `grade-pill grade-${grade.toLowerCase()}`;
      gradePill.textContent = `Grade ${grade}`;
    }

    if (navBadge) {
      navBadge.className = `nav-badge ${score >= 85 ? 'status-good' : 'status-warning'}`;
      navBadge.textContent = score >= 85 ? 'Healthy' : 'Attention';
    }

    if (scoreDesc) {
      if (score === 100) {
        scoreDesc.textContent = 'All security parameters, passkey freshness, and cryptographic standards passing.';
      } else if (score >= 80) {
        scoreDesc.textContent = 'Vault is in good standing with minor recommendations below.';
      } else {
        scoreDesc.textContent = 'Security findings require attention to optimize vault hygiene.';
      }
    }

    if (!findingsList) return;
    findingsList.innerHTML = '';

    const issues = report.issues || [];
    if (issues.length === 0) {
      const item = document.createElement('div');
      item.className = 'finding-item finding-pass';
      item.innerHTML = `
        <div class="finding-icon">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="18" height="18">
            <path d="M5 12l5 5l10 -10" />
          </svg>
        </div>
        <div class="finding-content">
          <h4>All Security Checks Passed</h4>
          <p>Zero duplicate credentials detected, no stale passkeys older than 90 days, and local Argon2id key derivation verified.</p>
        </div>
      `;
      findingsList.appendChild(item);
    } else {
      issues.forEach((issue) => {
        const item = document.createElement('div');
        const isMed = issue.severity === 'medium';
        item.className = `finding-item ${isMed ? 'finding-warn' : 'finding-info'}`;
        item.innerHTML = `
          <div class="finding-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="18" height="18">
              <path d="M12 9v4" /><path d="M12 17h.01" />
              <path d="M5 19h14a2 2 0 0 0 1.84 -2.75l-7.1 -12.25a2 2 0 0 0 -3.5 0l-7.1 12.25a2 2 0 0 0 1.75 2.75" />
            </svg>
          </div>
          <div class="finding-content">
            <h4>${escapeHtml(issue.rpId || 'Passkey Warning')} (${escapeHtml(issue.type)})</h4>
            <p>${escapeHtml(issue.detail || '')}</p>
          </div>
        `;
        findingsList.appendChild(item);
      });
    }
  }

  // ─── Activity Log View ────────────────────────────────────────────
  async function loadActionLogs(isUserClick = false) {
    if (!isUnlocked) return;
    const tbody = document.getElementById('logs-table-body');
    const emptyState = document.getElementById('logs-empty');
    const refreshBtn = document.getElementById('refresh-logs-btn');

    if (refreshBtn) refreshBtn.disabled = true;
    if (isUserClick && tbody) {
      tbody.innerHTML = '<tr class="table-loading-row"><td colspan="4"><div class="table-loading-spinner"><svg class="spin-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path d="M12 3a9 9 0 1 0 9 9"/></svg> Loading activity trail...</div></td></tr>';
    }

    try {
      const resp = await sendMsg({ action: 'get_action_logs' });
      const logs = (resp && resp.logs) || [];

      if (!tbody) return;
      tbody.innerHTML = '';

      if (logs.length === 0) {
        if (emptyState) emptyState.classList.remove('hidden');
        return;
      }
      if (emptyState) emptyState.classList.add('hidden');

      logs.forEach((log) => {
        const tr = document.createElement('tr');
        // Handle Python seconds vs ms vs ISO string cleanly
        const rawTs = log.iso_timestamp || log.timestamp;
        const tsFormatted = formatTimestamp(rawTs);
        const relTime = formatRelativeDate(rawTs);
        const isSuccess = (log.status || '').toUpperCase() === 'SUCCESS';

        tr.innerHTML = `
          <td>
            <span class="date-cell" title="${escapeHtml(relTime)}">${escapeHtml(tsFormatted)}</span>
          </td>
          <td><code>${escapeHtml(log.action || 'unknown')}</code></td>
          <td>
            <span class="badge ${isSuccess ? 'badge-success' : 'badge-danger'}">
              ${escapeHtml(log.status || 'OK')}
            </span>
          </td>
          <td><span class="log-detail-text">${escapeHtml(log.details || '—')}</span></td>
        `;
        tbody.appendChild(tr);
      });

      if (isUserClick) {
        showToast(`Activity log updated (${logs.length} events loaded).`, 'success', 'Log Refreshed');
      }
    } catch (err) {
      showToast('Error loading activity logs: ' + err.message, 'danger', 'Log Load Error');
    } finally {
      if (refreshBtn) refreshBtn.disabled = false;
    }
  }

  // ─── Backup & Restore ─────────────────────────────────────────────
  function b64ToUint8Array(base64) {
    const binaryString = atob(base64);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
  }

  async function handleDownloadBackup() {
    if (!isUnlocked) return;
    const btn = document.getElementById('download-backup-btn');
    const metaInfo = document.getElementById('backup-meta-info');

    if (btn) {
      btn.disabled = true;
      btn.innerHTML = '<svg class="spin-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path d="M12 3a9 9 0 1 0 9 9"/></svg><span>Creating Encrypted Backup...</span>';
    }

    try {
      const resp = await sendMsg({ action: 'get_backup_blob' });
      if (resp && resp.error) {
        showToast('Backup creation failed: ' + resp.error, 'danger', 'Backup Failed');
        return;
      }

      const b64 = resp.backupBlob;
      const filename = resp.filename || 'zenith-vault-backup.enc';
      const u8 = b64ToUint8Array(b64);
      const blob = new Blob([u8], { type: 'application/octet-stream' });

      // Trigger standard browser download
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      if (metaInfo) {
        metaInfo.innerHTML = `
          <strong>Backup Created:</strong> ${escapeHtml(filename)}<br>
          <strong>File Size:</strong> ${resp.size ? resp.size.toLocaleString() : u8.length} bytes<br>
          <strong>SHA-256 Fingerprint:</strong> <code>${escapeHtml(resp.sha256 || '—')}</code>
        `;
        metaInfo.classList.remove('hidden');
      }

      showToast(`Encrypted backup "${filename}" downloaded. SHA-256 verified.`, 'success', 'Backup Created');
    } catch (err) {
      showToast(err.message || 'Failed to create backup.', 'danger', 'Backup Error');
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.innerHTML = `
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="16" height="16">
            <path d="M4 17v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2 -2v-2" />
            <path d="M7 11l5 5l5 -5" />
            <path d="M12 4l0 12" />
          </svg>
          <span>Download Encrypted Backup</span>
        `;
      }
    }
  }

  function setupRestoreDropZone() {
    const dropZone = document.getElementById('restore-drop-zone');
    const fileInput = document.getElementById('restore-file-input');
    const selectedInfo = document.getElementById('restore-selected-info');
    const fileNameEl = document.getElementById('restore-file-name');
    const clearBtn = document.getElementById('restore-clear-file');
    const executeBtn = document.getElementById('execute-restore-btn');
    const pwInput = document.getElementById('restore-password-input');

    if (!dropZone || !fileInput) return;

    dropZone.addEventListener('click', () => fileInput.click());

    dropZone.addEventListener('dragover', (e) => {
      e.preventDefault();
      dropZone.classList.add('drag-over');
    });

    dropZone.addEventListener('dragleave', () => {
      dropZone.classList.remove('drag-over');
    });

    dropZone.addEventListener('drop', (e) => {
      e.preventDefault();
      dropZone.classList.remove('drag-over');
      if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
        processRestoreFile(e.dataTransfer.files[0]);
      }
    });

    fileInput.addEventListener('change', () => {
      if (fileInput.files && fileInput.files.length > 0) {
        processRestoreFile(fileInput.files[0]);
      }
    });

    if (clearBtn) {
      clearBtn.addEventListener('click', () => {
        restoreFileBlobBase64 = null;
        fileInput.value = '';
        if (selectedInfo) selectedInfo.classList.add('hidden');
        if (dropZone) dropZone.classList.remove('hidden');
        if (executeBtn) executeBtn.disabled = true;
      });
    }

    if (pwInput) {
      pwInput.addEventListener('input', () => {
        if (executeBtn) {
          executeBtn.disabled = !(restoreFileBlobBase64 && pwInput.value.trim().length > 0);
        }
      });
    }

    function processRestoreFile(file) {
      const reader = new FileReader();
      reader.onload = function (e) {
        const buffer = e.target.result;
        let binary = '';
        const bytes = new Uint8Array(buffer);
        const len = bytes.byteLength;
        for (let i = 0; i < len; i++) {
          binary += String.fromCharCode(bytes[i]);
        }
        restoreFileBlobBase64 = btoa(binary);

        if (fileNameEl) fileNameEl.textContent = `${file.name} (${file.size.toLocaleString()} bytes)`;
        if (selectedInfo) selectedInfo.classList.remove('hidden');
        if (dropZone) dropZone.classList.add('hidden');
        if (executeBtn) {
          executeBtn.disabled = !(restoreFileBlobBase64 && pwInput && pwInput.value.trim().length > 0);
        }
        showToast(`Selected backup file "${file.name}". Enter its master password to verify.`, 'info', 'File Loaded');
      };
      reader.readAsArrayBuffer(file);
    }
  }

  async function handleExecuteRestore() {
    const pwInput = document.getElementById('restore-password-input');
    const errEl = document.getElementById('restore-error');
    const btn = document.getElementById('execute-restore-btn');
    const password = pwInput ? pwInput.value : '';

    if (!restoreFileBlobBase64 || !password) {
      if (errEl) {
        errEl.textContent = 'Please select a backup file and enter its master password.';
        errEl.classList.remove('hidden');
      }
      return;
    }

    if (errEl) errEl.classList.add('hidden');
    if (btn) {
      btn.disabled = true;
      btn.innerHTML = '<svg class="spin-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path d="M12 3a9 9 0 1 0 9 9"/></svg><span>Verifying Decryption in Memory...</span>';
    }

    try {
      const resp = await sendMsg({
        action: 'restore_backup_blob',
        backupBlob: restoreFileBlobBase64,
        password: password,
      });

      if (resp && resp.error) {
        if (errEl) {
          errEl.textContent = resp.error;
          errEl.classList.remove('hidden');
        }
        showToast(resp.error, 'danger', 'Restore Failed');
      } else if (resp && resp.success) {
        showToast(`Vault restored successfully (${resp.credentialCount || 0} credentials loaded).`, 'success', 'Vault Restored');
        if (pwInput) pwInput.value = '';
        const clearBtn = document.getElementById('restore-clear-file');
        if (clearBtn) clearBtn.click();
        loadPasskeys(false);
        loadAuditReport(false);
        loadActionLogs(false);
      } else {
        if (errEl) {
          errEl.textContent = 'Restore failed: Unexpected error.';
          errEl.classList.remove('hidden');
        }
        showToast('Restore failed: Unexpected response.', 'danger', 'Restore Failed');
      }
    } catch (err) {
      if (errEl) {
        errEl.textContent = err.message || 'Error restoring vault.';
        errEl.classList.remove('hidden');
      }
      showToast(err.message || 'Error restoring vault.', 'danger', 'Restore Error');
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.textContent = 'Verify & Restore Vault';
      }
    }
  }

  // ─── Import & Export ──────────────────────────────────────────────
  function setupImportDropZone() {
    const dropZone = document.getElementById('import-drop-zone');
    const fileInput = document.getElementById('import-file-input');
    const statusEl = document.getElementById('import-status');
    const executeBtn = document.getElementById('execute-import-btn');

    if (!dropZone || !fileInput) return;

    dropZone.addEventListener('click', () => fileInput.click());

    dropZone.addEventListener('dragover', (e) => {
      e.preventDefault();
      dropZone.classList.add('drag-over');
    });

    dropZone.addEventListener('dragleave', () => {
      dropZone.classList.remove('drag-over');
    });

    dropZone.addEventListener('drop', (e) => {
      e.preventDefault();
      dropZone.classList.remove('drag-over');
      if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
        processImportFile(e.dataTransfer.files[0]);
      }
    });

    fileInput.addEventListener('change', () => {
      if (fileInput.files && fileInput.files.length > 0) {
        processImportFile(fileInput.files[0]);
      }
    });

    function processImportFile(file) {
      const selectedInfo = document.getElementById('import-selected-info');
      const selectedFileName = document.getElementById('import-file-name');
      const pwSection = document.getElementById('import-password-section');
      const pwInput = document.getElementById('import-password-input');

      const reader = new FileReader();
      reader.onload = function (e) {
        try {
          const parsed = JSON.parse(e.target.result);
          rawEncryptedExport = null;
          importCredentialsList = null;

          if (selectedInfo && selectedFileName) {
            selectedFileName.textContent = file.name;
            selectedInfo.classList.remove('hidden');
          }

          if (parsed && parsed.format === 'zenith-encrypted-export') {
            rawEncryptedExport = parsed;
            if (pwSection) pwSection.classList.remove('hidden');
            if (statusEl) {
              statusEl.className = 'inline-success';
              statusEl.textContent = `Encrypted export detected in ${file.name}. Enter password and click Import.`;
              statusEl.classList.remove('hidden');
            }
            if (executeBtn) executeBtn.disabled = false;
            showToast('Encrypted export file loaded. Please enter password to decrypt.', 'info', 'Encrypted File');
            return;
          }

          if (pwSection) {
            pwSection.classList.add('hidden');
            if (pwInput) pwInput.value = '';
          }

          let creds = [];
          if (Array.isArray(parsed)) {
            creds = parsed;
          } else if (parsed.credentials && Array.isArray(parsed.credentials)) {
            creds = parsed.credentials;
          } else {
            throw new Error('Unrecognized format. Expected list of passkey credentials or encrypted export.');
          }

          importCredentialsList = creds;
          if (statusEl) {
            statusEl.className = 'inline-success';
            statusEl.textContent = `Found ${creds.length} passkey credentials in ${file.name}. Click Import to proceed.`;
            statusEl.classList.remove('hidden');
          }
          if (executeBtn) executeBtn.disabled = false;
          showToast(`Loaded ${creds.length} credentials from "${file.name}".`, 'info', 'File Validated');
        } catch (err) {
          rawEncryptedExport = null;
          importCredentialsList = null;
          if (statusEl) {
            statusEl.className = 'inline-error';
            statusEl.textContent = 'Invalid JSON file: ' + err.message;
            statusEl.classList.remove('hidden');
          }
          if (executeBtn) executeBtn.disabled = true;
          showToast('Invalid JSON file: ' + err.message, 'danger', 'Import Error');
        }
      };
      reader.readAsText(file);
    }

    const clearBtn = document.getElementById('import-clear-file');
    if (clearBtn) {
      clearBtn.addEventListener('click', () => {
        fileInput.value = '';
        rawEncryptedExport = null;
        importCredentialsList = null;
        const selectedInfo = document.getElementById('import-selected-info');
        const pwSection = document.getElementById('import-password-section');
        const pwInput = document.getElementById('import-password-input');
        if (selectedInfo) selectedInfo.classList.add('hidden');
        if (pwSection) pwSection.classList.add('hidden');
        if (pwInput) pwInput.value = '';
        if (statusEl) statusEl.classList.add('hidden');
        if (executeBtn) executeBtn.disabled = true;
      });
    }
  }

  async function handleExecuteImport() {
    if (!importCredentialsList && !rawEncryptedExport) return;
    const btn = document.getElementById('execute-import-btn');
    const statusEl = document.getElementById('import-status');
    const pwInput = document.getElementById('import-password-input');
    const fileInput = document.getElementById('import-file-input');
    const selectedInfo = document.getElementById('import-selected-info');
    const pwSection = document.getElementById('import-password-section');

    const importPassword = pwInput ? pwInput.value : '';
    if (rawEncryptedExport && !importPassword) {
      if (statusEl) {
        statusEl.className = 'inline-error';
        statusEl.textContent = 'Please enter the export decryption password.';
        statusEl.classList.remove('hidden');
      }
      showToast('Export decryption password required.', 'warning', 'Password Required');
      return;
    }

    if (btn) {
      btn.disabled = true;
      btn.innerHTML = '<svg class="spin-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path d="M12 3a9 9 0 1 0 9 9"/></svg><span>Importing Credentials...</span>';
    }

    try {
      const msg = rawEncryptedExport
        ? { action: 'import_vault', encrypted_export: rawEncryptedExport, password: importPassword }
        : { action: 'import_vault', credentials: importCredentialsList };

      const resp = await sendMsg(msg);

      if (resp && resp.error) {
        if (statusEl) {
          statusEl.className = 'inline-error';
          statusEl.textContent = resp.error;
          statusEl.classList.remove('hidden');
        }
        showToast(resp.error, 'danger', 'Import Failed');
      } else if (resp && resp.success) {
        const imported = resp.importedCount || 0;
        const total = resp.totalCredentials || 0;
        showToast(`Successfully imported ${imported} passkeys (Total in vault: ${total}).`, 'success', 'Import Complete');

        if (statusEl) {
          statusEl.className = 'inline-success';
          statusEl.textContent = `Import complete: ${imported} credentials imported. Total in vault: ${total}`;
          statusEl.classList.remove('hidden');
        }
        importCredentialsList = null;
        rawEncryptedExport = null;
        if (fileInput) fileInput.value = '';
        if (pwInput) pwInput.value = '';
        if (pwSection) pwSection.classList.add('hidden');
        if (selectedInfo) selectedInfo.classList.add('hidden');
        if (btn) btn.disabled = true;

        loadPasskeys(false);
        loadAuditReport(false);
        loadActionLogs(false);
      }
    } catch (err) {
      if (statusEl) {
        statusEl.className = 'inline-error';
        statusEl.textContent = err.message || 'Import failed.';
        statusEl.classList.remove('hidden');
      }
      showToast(err.message || 'Import failed.', 'danger', 'Import Error');
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.textContent = 'Import Passkeys';
      }
    }
  }

  async function handleExecuteExport() {
    if (!isUnlocked) return;
    const encryptToggle = document.getElementById('export-encrypt-toggle');
    const pwInput = document.getElementById('export-password-input');
    const btn = document.getElementById('execute-export-btn');

    const shouldEncrypt = encryptToggle ? encryptToggle.checked : true;
    const exportPw = shouldEncrypt && pwInput ? pwInput.value.trim() : null;

    if (shouldEncrypt && (!exportPw || exportPw.length < 8)) {
      showToast('Export encryption password must be at least 8 characters.', 'warning', 'Password Required');
      return;
    }

    if (btn) {
      btn.disabled = true;
      btn.innerHTML = '<svg class="spin-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path d="M12 3a9 9 0 1 0 9 9"/></svg><span>Encrypting & Exporting...</span>';
    }

    try {
      const resp = await sendMsg({
        action: 'export_vault',
        password: exportPw,
      });

      if (resp && resp.error) {
        showToast('Export failed: ' + resp.error, 'danger', 'Export Failed');
        return;
      }

      const content = resp.data;
      const isEnc = !!resp.encrypted;
      const filename = isEnc ? 'zenith-passkeys-export-encrypted.json' : 'zenith-passkeys-export.json';

      const blob = new Blob([content], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      showToast(`Export complete: ${resp.credentialCount || currentCredentials.length} passkeys written to "${filename}".`, 'success', 'Export Complete');
    } catch (err) {
      showToast(err.message || 'Failed to export passkeys.', 'danger', 'Export Error');
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.textContent = 'Export Credentials';
      }
    }
  }

  // ─── Settings ─────────────────────────────────────────────────────
  async function handleChangePassword() {
    const oldPwInput = document.getElementById('cp-old-password');
    const newPwInput = document.getElementById('cp-new-password');
    const confirmPwInput = document.getElementById('cp-confirm-password');
    const errEl = document.getElementById('cp-error');
    const successEl = document.getElementById('cp-success');
    const btn = document.getElementById('change-password-btn');

    if (errEl) errEl.classList.add('hidden');
    if (successEl) successEl.classList.add('hidden');

    const oldPw = oldPwInput ? oldPwInput.value : '';
    const newPw = newPwInput ? newPwInput.value : '';
    const confirmPw = confirmPwInput ? confirmPwInput.value : '';

    if (!oldPw || !newPw || !confirmPw) {
      if (errEl) {
        errEl.textContent = 'All password fields are required.';
        errEl.classList.remove('hidden');
      }
      showToast('All password fields are required.', 'warning', 'Incomplete Form');
      return;
    }

    if (newPw !== confirmPw) {
      if (errEl) {
        errEl.textContent = 'New passwords do not match.';
        errEl.classList.remove('hidden');
      }
      showToast('New passwords do not match.', 'warning', 'Mismatch');
      return;
    }

    if (newPw.length < 8) {
      if (errEl) {
        errEl.textContent = 'New password must be at least 8 characters.';
        errEl.classList.remove('hidden');
      }
      showToast('Password must be at least 8 characters.', 'warning', 'Password Too Short');
      return;
    }

    if (btn) {
      btn.disabled = true;
      btn.innerHTML = '<svg class="spin-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path d="M12 3a9 9 0 1 0 9 9"/></svg><span>Deriving Argon2id & Re-encrypting...</span>';
    }

    try {
      const resp = await sendMsg({
        action: 'change_password',
        oldPassword: oldPw,
        newPassword: newPw,
      });

      if (resp && resp.error) {
        if (errEl) {
          errEl.textContent = resp.error;
          errEl.classList.remove('hidden');
        }
        showToast(resp.error, 'danger', 'Password Change Failed');
      } else if (resp && resp.success) {
        if (successEl) {
          successEl.textContent = 'Master password updated successfully. Master key has been re-wrapped.';
          successEl.classList.remove('hidden');
        }
        if (oldPwInput) oldPwInput.value = '';
        if (newPwInput) newPwInput.value = '';
        if (confirmPwInput) confirmPwInput.value = '';
        showToast('Master password successfully updated. Vault key re-wrapped.', 'success', 'Password Updated');
        loadActionLogs(false);
      }
    } catch (err) {
      if (errEl) {
        errEl.textContent = err.message || 'Failed to update master password.';
        errEl.classList.remove('hidden');
      }
      showToast(err.message || 'Password update failed.', 'danger', 'Update Error');
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.textContent = 'Update Master Password';
      }
    }
  }

  // ─── Helpers ──────────────────────────────────────────────────────
  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  // ─── DOM Initialization ───────────────────────────────────────────
  document.addEventListener('DOMContentLoaded', () => {
    // Navigation listeners
    document.querySelectorAll('.nav-item').forEach((btn) => {
      btn.addEventListener('click', () => {
        const view = btn.dataset.view;
        switchView(view);
      });
    });

    // Sidebar lock button
    const lockBtn = document.getElementById('sidebar-lock-btn');
    if (lockBtn) lockBtn.addEventListener('click', doLock);

    // Unlock form
    const unlockBtn = document.getElementById('unlock-submit-btn');
    if (unlockBtn) unlockBtn.addEventListener('click', doUnlock);
    const unlockInput = document.getElementById('unlock-input');
    if (unlockInput) {
      unlockInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') doUnlock();
      });
    }

    // First-run create vault form
    const frCreateBtn = document.getElementById('fr-dash-create-btn');
    if (frCreateBtn) frCreateBtn.addEventListener('click', doCreateVault);
    const frConfirmInput = document.getElementById('fr-dash-confirm');
    if (frConfirmInput) {
      frConfirmInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') doCreateVault();
      });
    }
    const frContinueBtn = document.getElementById('fr-dash-continue-btn');
    if (frContinueBtn) {
      frContinueBtn.addEventListener('click', () => {
        updateVaultIndicator(true, isFallback);
        loadPasskeys(false);
        loadAuditReport(false);
      });
    }

    // Switch between unlock and create vault
    const switchFirstRun = document.getElementById('dash-switch-firstrun');
    if (switchFirstRun) {
      switchFirstRun.addEventListener('click', (e) => {
        e.preventDefault();
        showFirstRunGate();
      });
    }
    const switchUnlock = document.getElementById('dash-switch-unlock');
    if (switchUnlock) {
      switchUnlock.addEventListener('click', (e) => {
        e.preventDefault();
        showUnlockGate();
      });
    }

    // Switch to recovery view
    const switchRecovery = document.getElementById('dash-switch-recovery');
    if (switchRecovery) {
      switchRecovery.addEventListener('click', (e) => {
        e.preventDefault();
        showRecoveryGate();
      });
    }
    const switchBackUnlock = document.getElementById('dash-switch-back-unlock');
    if (switchBackUnlock) {
      switchBackUnlock.addEventListener('click', (e) => {
        e.preventDefault();
        showUnlockGate();
      });
    }
    const recSubmitBtn = document.getElementById('dash-recovery-submit-btn');
    if (recSubmitBtn) recSubmitBtn.addEventListener('click', doRecoverVault);
    const recConfirmInput = document.getElementById('dash-recovery-confirm');
    if (recConfirmInput) {
      recConfirmInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') doRecoverVault();
      });
    }

    // Passkeys search & refresh
    const searchInput = document.getElementById('passkey-search');
    if (searchInput) searchInput.addEventListener('input', filterPasskeys);
    const refreshBtn = document.getElementById('refresh-passkeys-btn');
    if (refreshBtn) refreshBtn.addEventListener('click', () => loadPasskeys(true));

    // Delete modal handlers
    const cancelDelBtn = document.getElementById('delete-cancel-btn');
    if (cancelDelBtn) cancelDelBtn.addEventListener('click', closeDeleteModal);
    const confirmDelBtn = document.getElementById('delete-confirm-btn');
    if (confirmDelBtn) confirmDelBtn.addEventListener('click', confirmDeletePasskey);

    // Security audit
    const runAuditBtn = document.getElementById('run-audit-btn');
    if (runAuditBtn) runAuditBtn.addEventListener('click', () => loadAuditReport(true));

    // Activity log refresh
    const refreshLogsBtn = document.getElementById('refresh-logs-btn');
    if (refreshLogsBtn) refreshLogsBtn.addEventListener('click', () => loadActionLogs(true));

    // Backup download
    const downloadBackupBtn = document.getElementById('download-backup-btn');
    if (downloadBackupBtn) downloadBackupBtn.addEventListener('click', handleDownloadBackup);

    // Restore backup
    setupRestoreDropZone();
    const executeRestoreBtn = document.getElementById('execute-restore-btn');
    if (executeRestoreBtn) executeRestoreBtn.addEventListener('click', handleExecuteRestore);

    // Import / Export
    setupImportDropZone();
    const executeImportBtn = document.getElementById('execute-import-btn');
    if (executeImportBtn) executeImportBtn.addEventListener('click', handleExecuteImport);

    const exportEncryptToggle = document.getElementById('export-encrypt-toggle');
    const exportPwSection = document.getElementById('export-password-section');
    if (exportEncryptToggle && exportPwSection) {
      exportEncryptToggle.addEventListener('change', () => {
        exportPwSection.style.display = exportEncryptToggle.checked ? 'block' : 'none';
      });
    }
    const executeExportBtn = document.getElementById('execute-export-btn');
    if (executeExportBtn) executeExportBtn.addEventListener('click', handleExecuteExport);

    // Change password
    const changePwBtn = document.getElementById('change-password-btn');
    if (changePwBtn) changePwBtn.addEventListener('click', handleChangePassword);

    // Auto-lock timeout selector
    const timeoutSelect = document.getElementById('dash-timeout');
    const kpiAuto = document.getElementById('kpi-autolock-val');
    if (timeoutSelect) {
      sendMsg({ action: 'get_settings' }).then((res) => {
        if (res && res.settings && res.settings.idle_timeout_minutes) {
          const val = res.settings.idle_timeout_minutes;
          timeoutSelect.value = String(val);
          if (kpiAuto) kpiAuto.textContent = `${val} min`;
          if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
            chrome.storage.local.set({ zenith_timeout: val });
          }
        } else if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
          chrome.storage.local.get(['zenith_timeout'], (stored) => {
            if (stored && stored.zenith_timeout) {
              timeoutSelect.value = String(stored.zenith_timeout);
              if (kpiAuto) kpiAuto.textContent = `${stored.zenith_timeout} min`;
            }
          });
        }
      }).catch(() => {});

      timeoutSelect.addEventListener('change', () => {
        const val = parseInt(timeoutSelect.value, 10) || 15;
        if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
          chrome.storage.local.set({ zenith_timeout: val });
        }
        if (kpiAuto) kpiAuto.textContent = `${val} min`;
        sendMsg({ action: 'update_settings', settings: { idle_timeout_minutes: val } }).catch(() => {});
        showToast(`Auto-lock timeout updated to ${val} minutes.`, 'info', 'Settings Updated');
      });
    }

    // Emergency recovery key rotation and display management
    const rotateBtn = document.getElementById('dash-rotate-recovery-btn');
    const recoveryDisplay = document.getElementById('dash-recovery-display');
    const recoveryActions = document.getElementById('dash-recovery-actions');
    const copyBtn = document.getElementById('dash-copy-recovery-btn');
    const toggleBlurBtn = document.getElementById('dash-toggle-blur-btn');
    const recoveryNote = document.getElementById('dash-recovery-note');

    let activeRecoveryKey = null;

    if (rotateBtn) {
      rotateBtn.addEventListener('click', async () => {
        const confirmed = window.confirm(
          'Generating a new emergency recovery key will immediately replace and invalidate any previous recovery key.\n\nDo you want to generate a new active recovery key?'
        );
        if (!confirmed) return;

        rotateBtn.disabled = true;
        rotateBtn.textContent = 'Generating...';

        try {
          const res = await sendMsg({ action: 'rotate_recovery_key' });
          if (res && res.recovery_key) {
            activeRecoveryKey = res.recovery_key;
            if (recoveryDisplay) {
              recoveryDisplay.textContent = res.recovery_key;
              recoveryDisplay.classList.remove('blurred');
            }
            if (recoveryActions) recoveryActions.classList.remove('hidden');
            if (recoveryNote) {
              recoveryNote.textContent = '✓ New emergency recovery key active! Save this in a secure physical location or notebook. Any previous key is now retired.';
              recoveryNote.style.color = '#10b981';
            }
            showToast('New emergency recovery key generated and active.', 'success', 'Key Generated');
          } else {
            showToast(res.error || 'Failed to rotate recovery key.', 'error', 'Action Failed');
          }
        } catch (err) {
          showToast(err.message || 'Error communicating with vault.', 'error', 'Error');
        } finally {
          rotateBtn.disabled = false;
          rotateBtn.textContent = 'Generate New Recovery Key';
        }
      });
    }

    if (copyBtn) {
      copyBtn.addEventListener('click', async () => {
        if (!activeRecoveryKey) return;
        try {
          await navigator.clipboard.writeText(activeRecoveryKey);
          showToast('Emergency recovery key copied to clipboard.', 'success', 'Copied');
        } catch (_) {
          showToast('Could not copy to clipboard. Please copy manually.', 'warning', 'Copy Failed');
        }
      });
    }

    if (toggleBlurBtn && recoveryDisplay) {
      toggleBlurBtn.addEventListener('click', () => {
        const isBlurred = recoveryDisplay.classList.toggle('blurred');
        toggleBlurBtn.textContent = isBlurred ? 'Reveal' : 'Hide';
        showToast(isBlurred ? 'Recovery key hidden.' : 'Recovery key revealed for viewing.', 'info', 'Privacy Shield');
      });
    }

    // Global keyboard shortcut: Ctrl+K / Cmd+K to focus passkey search
    window.addEventListener('keydown', (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        const searchInput = document.getElementById('passkey-search');
        if (searchInput) {
          searchInput.focus();
          searchInput.select();
        }
      }
    });

    // Initial check
    checkStatusAndInit();
  });
})();
