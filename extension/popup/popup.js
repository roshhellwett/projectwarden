function showView(id) {
  document.querySelectorAll('.view').forEach(v => v.classList.add('hidden'));
  document.getElementById(id).classList.remove('hidden');
}

async function initPopup() {
  const status = await chrome.runtime.sendMessage({ action: 'get_status' });
  if (status.fallback) {
    document.getElementById('fallback-banner').classList.remove('hidden');
  }
  document.getElementById('set-host-status').textContent = status.unlocked ? 'Connected' : 'Disconnected';

  if (status.unlocked) {
    showView('view-main');
    loadCredentials();
  } else {
    showView('view-unlock');
  }
}

document.getElementById('ul-unlock').addEventListener('click', async () => {
  const pw = document.getElementById('ul-password').value;
  if (!pw) return;
  await chrome.runtime.sendMessage({ action: 'unlock', password: pw });
  initPopup();
});

document.getElementById('ul-recovery').addEventListener('click', () => {
  showView('view-firstrun');
  document.querySelector('#view-firstrun h2').textContent = 'Recover Vault';
  document.getElementById('fr-create').textContent = 'Recover';
});

document.getElementById('fr-create').addEventListener('click', async () => {
  const pw = document.getElementById('fr-password').value;
  const confirm = document.getElementById('fr-confirm').value;
  if (pw !== confirm) return alert('Passwords do not match');
  const recoveryKey = await chrome.runtime.sendMessage({ action: 'create_vault', password: pw });
  if (recoveryKey.recovery_key) {
    document.getElementById('fr-recovery-key').textContent = recoveryKey.recovery_key;
    document.getElementById('fr-create').classList.add('hidden');
    document.getElementById('fr-password').classList.add('hidden');
    document.getElementById('fr-confirm').classList.add('hidden');
    document.getElementById('fr-recovery').classList.remove('hidden');
  }
});

document.getElementById('fr-checkbox').addEventListener('change', (e) => {
  document.getElementById('fr-continue').disabled = !e.target.checked;
});

document.getElementById('fr-continue').addEventListener('click', () => {
  initPopup();
});

async function loadCredentials() {
  const list = document.getElementById('cred-list');
  list.innerHTML = '<p style="color:var(--text-muted);font-size:13px;">Loading...</p>';
  try {
    const result = await chrome.runtime.sendMessage({ action: 'list_credentials' });
    if (result.credentials) {
      renderCredentials(result.credentials);
    }
  } catch (e) {
    list.innerHTML = '<p style="color:var(--danger);font-size:13px;">Failed to load.</p>';
  }
}

function renderCredentials(creds) {
  const list = document.getElementById('cred-list');
  if (!creds.length) {
    list.innerHTML = '<p style="color:var(--text-muted);font-size:13px;">No credentials stored.</p>';
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
      html += `<div class="cred-item">
        <div class="domain">${domain}</div>
        <div class="username">${c.username}</div>
        <div class="last-used">Used: ${last}</div>
      </div>`;
    });
  });
  list.innerHTML = html;
}

document.getElementById('cred-search').addEventListener('input', (e) => {
  const q = e.target.value.toLowerCase();
  document.querySelectorAll('.cred-item').forEach(el => {
    const domain = el.querySelector('.domain').textContent.toLowerCase();
    el.style.display = domain.includes(q) ? '' : 'none';
  });
});

document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    tab.classList.add('active');
    document.querySelectorAll('.tab-content').forEach(tc => tc.classList.add('hidden'));
    document.getElementById('tab-' + tab.dataset.tab).classList.remove('hidden');
  });
});

document.getElementById('set-lock').addEventListener('click', async () => {
  await chrome.runtime.sendMessage({ action: 'lock' });
  showView('view-unlock');
});

initPopup();
