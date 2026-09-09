const params = new URLSearchParams(location.search);
const action = params.get('action');
const origin = params.get('origin');
const confirmId = params.get('confirmId');

// SECURITY: this window is created by the background service worker with
// extension-origin URLs only (chrome.runtime.getURL). The origin shown here
// was derived from the SENDER TAB's URL, never from page-provided content.
document.getElementById('origin').textContent = origin || 'Unknown origin';

const actionEl = document.getElementById('action');
const unlockSection = document.getElementById('unlock-section');
const allowBtn = document.getElementById('btn-allow');

if (action === 'create') {
  actionEl.innerHTML = 'wants to register a new passkey. Allow only if you trust this site.';
} else if (action === 'verify') {
  // Re-verification demanded by the relying party (userVerification: required).
  // The password field is mandatory here: the site rejects unverified sign-ins.
  actionEl.innerHTML = 'requires user verification. Enter your master password to confirm it is you.';
  unlockSection.classList.add('show');
  unlockSection.querySelector('p').textContent = 'Master password';
  allowBtn.textContent = 'Verify & Continue';
  document.getElementById('unlock-password').focus();
} else {
  actionEl.innerHTML = 'wants to sign in with your passkey. Allow only if you initiated this.';
}

chrome.runtime.sendMessage({ action: 'is_unlocked' }, (response) => {
  if (action !== 'verify' && response && !response.unlocked) {
    unlockSection.classList.add('show');
    allowBtn.textContent = 'Unlock & Allow';
  }
});

async function allow() {
  const unlockSection = document.getElementById('unlock-section');
  if (unlockSection.classList.contains('show')) {
    const pwd = document.getElementById('unlock-password').value;
    if (!pwd) {
      document.getElementById('unlock-password').focus();
      return;
    }
    document.getElementById('btn-allow').textContent = 'Unlocking...';
    document.getElementById('btn-allow').disabled = true;

    const res = await new Promise(resolve => {
      chrome.runtime.sendMessage({ action: 'unlock', password: pwd }, resolve);
    });

    if (res && res.error) {
      const input = document.getElementById('unlock-password');
      input.value = '';
      input.focus();
      input.placeholder = 'Wrong password, try again';
      input.style.borderColor = 'var(--danger)';
      document.getElementById('btn-allow').textContent = 'Unlock & Allow';
      document.getElementById('btn-allow').disabled = false;
      return;
    }
  }

  chrome.runtime.sendMessage({ action: 'confirm_response', confirmId, allowed: true });
  window.close();
}

function deny() {
  chrome.runtime.sendMessage({ action: 'confirm_response', confirmId, allowed: false });
  window.close();
}

document.getElementById('btn-allow').addEventListener('click', allow);
document.getElementById('btn-deny').addEventListener('click', deny);
document.getElementById('unlock-password').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') {
    e.preventDefault();
    allow();
  }
});

function showError(msg, code) {
  document.getElementById('view-confirm').style.display = 'none';
  const errView = document.getElementById('view-error');
  errView.classList.add('show');
  const codeInput = document.getElementById('error-code-input');
  try {
    codeInput.value = code || btoa(unescape(encodeURIComponent(String(msg)))).substring(0, 50);
  } catch (e) {
    codeInput.value = String(msg).substring(0, 50);
  }
}

document.getElementById('error-copy-btn').addEventListener('click', async (e) => {
  const codeInput = document.getElementById('error-code-input');
  const text = codeInput ? codeInput.value : '';
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(text);
    } else {
      codeInput.select();
      document.execCommand('copy');
    }
    e.target.textContent = 'Copied!';
  } catch (err) {
    if (codeInput) {
      codeInput.select();
      document.execCommand('copy');
    }
    e.target.textContent = 'Copied!';
  }
  setTimeout(() => {
    if (e.target) e.target.textContent = 'Copy Error Code';
  }, 2000);
});

window.addEventListener('error', (e) => {
  showError(e.message, null);
});

window.addEventListener('unhandledrejection', (e) => {
  showError(e.reason?.message || 'Unknown Promise Rejection', null);
});
