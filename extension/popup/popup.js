// ─── State ───────────────────────────────────────────────────────
let currentCredentials = [];

// ─── View Management ─────────────────────────────────────────────
function showView(id) {
  document.querySelectorAll('.view').forEach(v => v.classList.add('hidden'));
  document.getElementById(id).classList.remove('hidden');
}

function showInlineError(elementId, message) {
  const el = document.getElementById(elementId);
  if (el) {
    el.textContent = message;
    el.classList.remove('hidden');
    setTimeout(() => el.classList.add('hidden'), 5000);
  }
}

function clearInlineError(elementId) {
  const el = document.getElementById(elementId);
  if (el) {
    el.textContent = '';
    el.classList.add('hidden');
  }
}

// ─── Toast Notifications ─────────────────────────────────────────
function showToast(message, type = 'success') {
  const container = document.getElementById('toast-container');
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.textContent = message;
  container.appendChild(toast);
  requestAnimationFrame(() => toast.classList.add('show'));
  setTimeout(() => {
    toast.classList.remove('show');
    setTimeout(() => toast.remove(), 300);
  }, 3000);
}

// ─── Loading States ──────────────────────────────────────────────
function setLoading(buttonId, loading) {
  const btn = document.getElementById(buttonId);
  if (!btn) return;
  if (loading) {
    btn.dataset.originalText = btn.textContent;
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span>' + (btn.dataset.loadingText || 'Working...');
  } else {
    btn.disabled = false;
    btn.textContent = btn.dataset.originalText || btn.textContent;
  }
}

// ─── Native messaging wrapper ────────────────────────────────────
// This wrapper does NOT throw on response.error — callers handle it
async function sendMsg(message) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(message, (response) => {
      if (chrome.runtime.lastError) {
        return reject(new Error(chrome.runtime.lastError.message));
      }
      resolve(response || {});
    });
  });
}

// ─── Init ────────────────────────────────────────────────────────
async function initPopup() {
  try {
    const status = await sendMsg({ action: 'get_status' });

    if (status.fallback) {
      document.getElementById('fallback-banner').classList.remove('hidden');
    }

    // Check if vault exists
    const existsResult = await sendMsg({ action: 'vault_exists' });
    const vaultExists = existsResult.exists;

    if (!vaultExists) {
      // First-time user — show create vault view
      showView('view-firstrun');
      return;
    }

    // Check if already unlocked
    const unlockedResult = await sendMsg({ action: 'is_unlocked' });

    if (unlockedResult.unlocked) {
      showView('view-main');
      loadCredentials();
      loadSettings();
    } else {
      showView('view-unlock');
    }
  } catch (e) {
    // If native host is completely unavailable, try fallback detection
    showView('view-unlock');
  }
}

// ─── Unlock ──────────────────────────────────────────────────────
document.getElementById('ul-unlock').addEventListener('click', doUnlock);
document.getElementById('ul-password').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') doUnlock();
});

async function doUnlock() {
  const pw = document.getElementById('ul-password').value;
  if (!pw) return;

  clearInlineError('ul-error');
  setLoading('ul-unlock', true);

  try {
    const result = await sendMsg({ action: 'unlock', password: pw });
    if (result.error) {
      showInlineError('ul-error', result.error === 'Vault is locked' ? 'Wrong password.' : (result.error || 'Wrong password.'));
      document.getElementById('ul-password').value = '';
      document.getElementById('ul-password').focus();
    } else {
      showView('view-main');
      loadCredentials();
      loadSettings();
    }
  } catch (e) {
    showInlineError('ul-error', 'Failed to connect. Is the native host installed?');
  } finally {
    setLoading('ul-unlock', false);
  }
}

// ─── Recovery link ───────────────────────────────────────────────
document.getElementById('ul-recovery').addEventListener('click', () => {
  showView('view-firstrun');
  document.querySelector('#view-firstrun h2').textContent = 'Recover Vault';
  document.getElementById('fr-create').textContent = 'Recover';
});

// ─── Create Vault ────────────────────────────────────────────────
document.getElementById('fr-create').addEventListener('click', doCreateVault);
document.getElementById('fr-password').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') document.getElementById('fr-confirm').focus();
});
document.getElementById('fr-confirm').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') doCreateVault();
});

async function doCreateVault() {
  const pw = document.getElementById('fr-password').value;
  const confirm = document.getElementById('fr-confirm').value;

  clearInlineError('fr-error');

  if (pw.length < 8) {
    showInlineError('fr-error', 'Password must be at least 8 characters.');
    return;
  }
  if (pw !== confirm) {
    showInlineError('fr-error', 'Passwords do not match.');
    return;
  }

  setLoading('fr-create', true);

  try {
    const result = await sendMsg({ action: 'create_vault', password: pw });
    if (result.error) {
      showInlineError('fr-error', result.error);
      return;
    }
    if (result.recovery_key) {
      document.getElementById('fr-recovery-key').textContent = result.recovery_key;
      document.getElementById('fr-create').classList.add('hidden');
      document.getElementById('fr-password').classList.add('hidden');
      document.getElementById('fr-confirm').classList.add('hidden');
      document.querySelector('#view-firstrun .strength-bar')?.classList.add('hidden');
      clearInlineError('fr-error');
      document.getElementById('fr-recovery').classList.remove('hidden');
    }
  } catch (e) {
    showInlineError('fr-error', 'Failed to create vault. Is the native host installed?');
  } finally {
    setLoading('fr-create', false);
  }
}

// ─── Password strength indicator ─────────────────────────────────
document.getElementById('fr-password').addEventListener('input', (e) => {
  const pw = e.target.value;
  const bar = document.getElementById('fr-strength-fill');
  const label = document.getElementById('fr-strength-label');
  if (!bar || !label) return;

  let strength = 0;
  if (pw.length >= 8) strength++;
  if (pw.length >= 12) strength++;
  if (/[A-Z]/.test(pw) && /[a-z]/.test(pw)) strength++;
  if (/[0-9]/.test(pw)) strength++;
  if (/[^A-Za-z0-9]/.test(pw)) strength++;

  const levels = [
    { width: '0%', color: '#e2e8f0', text: '' },
    { width: '20%', color: '#ef4444', text: 'Weak' },
    { width: '40%', color: '#f97316', text: 'Fair' },
    { width: '60%', color: '#eab308', text: 'Good' },
    { width: '80%', color: '#22c55e', text: 'Strong' },
    { width: '100%', color: '#10b981', text: 'Excellent' },
  ];

  const level = levels[Math.min(strength, levels.length - 1)];
  bar.style.width = level.width;
  bar.style.background = level.color;
  label.textContent = level.text;
  label.style.color = level.color;
});

// ─── Recovery key checkbox ───────────────────────────────────────
document.getElementById('fr-checkbox').addEventListener('change', (e) => {
  document.getElementById('fr-continue').disabled = !e.target.checked;
});

document.getElementById('fr-continue').addEventListener('click', () => {
  initPopup();
});

// ─── Load Credentials ────────────────────────────────────────────
async function loadCredentials() {
  const list = document.getElementById('cred-list');
  list.innerHTML = '<div class="loading-placeholder"><span class="spinner"></span> Loading credentials...</div>';

  try {
    const result = await sendMsg({ action: 'list_credentials' });
    if (result.error) {
      list.innerHTML = `<p class="error-text">${escapeHTML(result.error)}</p>`;
      return;
    }
    if (result.credentials) {
      currentCredentials = result.credentials;
      renderCredentials(result.credentials);
      // Update badge
      const badge = document.getElementById('cred-count');
      if (badge) badge.textContent = result.credentials.length;
    }
  } catch (e) {
    list.innerHTML = '<p class="error-text">Failed to load credentials.</p>';
  }
}

function escapeHTML(str) {
  return String(str).replace(/[&<>'"]/g,
    tag => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      "'": '&#39;',
      '"': '&quot;'
    }[tag] || tag)
  );
}

function renderCredentials(creds) {
  const list = document.getElementById('cred-list');
  if (!creds.length) {
    list.innerHTML = '<div class="empty-state"><div class="empty-icon">🔑</div><p>No passkeys stored yet.</p><p class="hint">Visit a site that supports passkeys to get started.</p></div>';
    return;
  }

  const groups = {};
  creds.forEach(c => {
    if (!groups[c.rpId]) groups[c.rpId] = [];
    groups[c.rpId].push(c);
  });

  let html = '';
  Object.entries(groups).forEach(([domain, entries]) => {
    entries.forEach(c => {
      const last = c.lastUsedAt ? new Date(c.lastUsedAt).toLocaleDateString() : 'Never';
      const created = c.createdAt ? new Date(c.createdAt).toLocaleDateString() : '—';
      html += `<div class="cred-item" data-credential-id="${escapeHTML(c.credentialId)}" data-rp-id="${escapeHTML(domain)}">
        <div class="cred-info">
          <div class="domain">${escapeHTML(domain)}</div>
          <div class="username">${escapeHTML(c.username || 'Unknown user')}</div>
          <div class="last-used">Last used: ${last}</div>
        </div>
        <button class="cred-delete" title="Delete credential" data-credential-id="${escapeHTML(c.credentialId)}">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
        </button>
      </div>`;
    });
  });
  list.innerHTML = html;

  // Attach delete handlers
  list.querySelectorAll('.cred-delete').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      e.stopPropagation();
      const credId = btn.dataset.credentialId;
      const item = btn.closest('.cred-item');
      const domain = item.dataset.rpId;

      if (!confirm(`Delete passkey for ${domain}?`)) return;

      btn.disabled = true;
      try {
        const result = await sendMsg({ action: 'delete_credential', credentialId: credId });
        if (result.error) {
          showToast(result.error, 'error');
        } else {
          item.style.animation = 'slideOut 0.3s ease forwards';
          setTimeout(() => {
            item.remove();
            showToast('Passkey deleted');
            // Update badge
            const badge = document.getElementById('cred-count');
            const remaining = document.querySelectorAll('.cred-item').length;
            if (badge) badge.textContent = remaining;
            if (remaining === 0) {
              loadCredentials(); // Show empty state
            }
          }, 300);
        }
      } catch (e) {
        showToast('Failed to delete credential', 'error');
        btn.disabled = false;
      }
    });
  });
}

// ─── Search ──────────────────────────────────────────────────────
document.getElementById('cred-search').addEventListener('input', (e) => {
  const q = e.target.value.toLowerCase();
  document.querySelectorAll('.cred-item').forEach(el => {
    const domain = el.querySelector('.domain').textContent.toLowerCase();
    const username = el.querySelector('.username').textContent.toLowerCase();
    el.style.display = (domain.includes(q) || username.includes(q)) ? '' : 'none';
  });
});

// ─── Tabs ────────────────────────────────────────────────────────
document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    tab.classList.add('active');
    document.querySelectorAll('.tab-content').forEach(tc => tc.classList.add('hidden'));
    document.getElementById('tab-' + tab.dataset.tab).classList.remove('hidden');
  });
});

// ─── Settings ────────────────────────────────────────────────────
async function loadSettings() {
  try {
    const result = await sendMsg({ action: 'get_settings' });
    if (result.settings) {
      const timeout = result.settings.idle_timeout_minutes || 15;
      document.getElementById('set-timeout').value = String(timeout);
    }
    // Update host status
    const status = await sendMsg({ action: 'get_status' });
    const hostEl = document.getElementById('set-host-status');
    if (status.fallback) {
      hostEl.textContent = 'Fallback (browser-only)';
      hostEl.style.color = 'var(--warning)';
    } else {
      hostEl.textContent = 'Connected';
      hostEl.style.color = 'var(--success)';
    }
  } catch (e) {
    // Ignore settings load failures
  }
}

document.getElementById('set-timeout').addEventListener('change', async (e) => {
  const timeout = parseInt(e.target.value, 10);
  try {
    const result = await sendMsg({ action: 'update_settings', settings: { idle_timeout_minutes: timeout } });
    if (result.error) {
      showToast(result.error, 'error');
    } else {
      showToast('Timeout updated');
    }
  } catch (e) {
    showToast('Failed to update settings', 'error');
  }
});

// ─── Lock ────────────────────────────────────────────────────────
document.getElementById('set-lock').addEventListener('click', async () => {
  await sendMsg({ action: 'lock' });
  showToast('Vault locked');
  setTimeout(() => initPopup(), 500);
});

// ─── Global Error Handlers ───────────────────────────────────────
function showFatalError(msg, code) {
  document.querySelectorAll('.view').forEach(v => v.classList.add('hidden'));
  const errView = document.getElementById('view-error');
  errView.classList.remove('hidden');
  const codeInput = document.getElementById('error-code-input');
  codeInput.value = code || btoa(msg).substring(0, 50);
}

document.getElementById('error-copy-btn').addEventListener('click', (e) => {
  const codeInput = document.getElementById('error-code-input');
  codeInput.select();
  navigator.clipboard.writeText(codeInput.value).then(() => {
    e.target.textContent = 'Copied!';
    setTimeout(() => e.target.textContent = 'Copy Error Code', 2000);
  }).catch(() => {
    document.execCommand('copy');
    e.target.textContent = 'Copied!';
    setTimeout(() => e.target.textContent = 'Copy Error Code', 2000);
  });
});

window.addEventListener('error', (e) => {
  showFatalError(e.message, null);
});

window.addEventListener('unhandledrejection', (e) => {
  showFatalError(e.reason?.message || 'Unknown Promise Rejection', null);
});

// ─── Start ───────────────────────────────────────────────────────
initPopup();
