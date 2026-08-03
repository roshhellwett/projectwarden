const params = new URLSearchParams(location.search);
const action = params.get('action');
const origin = params.get('origin');
const confirmId = params.get('confirmId');

document.getElementById('origin').textContent = origin || 'Unknown';
document.getElementById('action').textContent = action === 'create' ? 'Register new passkey' : 'Sign in with passkey';
document.getElementById('username').textContent = action === 'create' ? 'New credential will be created' : '';

chrome.runtime.sendMessage({ action: 'is_unlocked' }, (response) => {
  if (response && !response.unlocked) {
    document.getElementById('unlock-section').style.display = 'block';
    document.getElementById('btn-allow').textContent = 'Unlock & Allow';
  }
});

async function allow() {
  const unlockSection = document.getElementById('unlock-section');
  if (unlockSection.style.display !== 'none') {
    const pwd = document.getElementById('unlock-password').value;
    if (!pwd) {
      alert("Please enter your master password to continue");
      return;
    }
    document.getElementById('btn-allow').textContent = 'Unlocking...';
    document.getElementById('btn-allow').disabled = true;
    
    const res = await new Promise(resolve => {
      chrome.runtime.sendMessage({ action: 'unlock', password: pwd }, resolve);
    });
    
    if (res.error) {
      alert(res.error);
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
  document.querySelector('.icon').style.display = 'none';
  document.querySelector('h2').style.display = 'none';
  document.getElementById('origin').style.display = 'none';
  document.getElementById('action').style.display = 'none';
  document.getElementById('username').style.display = 'none';
  document.querySelector('.buttons').style.display = 'none';
  
  const errView = document.getElementById('view-error');
  errView.style.display = 'block';
  const codeInput = document.getElementById('error-code-input');
  codeInput.value = code || btoa(msg).substring(0, 50);
}

document.getElementById('error-copy-btn').addEventListener('click', (e) => {
  const codeInput = document.getElementById('error-code-input');
  codeInput.select();
  document.execCommand('copy');
  e.target.textContent = 'Copied!';
  setTimeout(() => e.target.textContent = 'Copy Error Code', 2000);
});

window.addEventListener('error', (e) => {
  showError(e.message, null);
});

window.addEventListener('unhandledrejection', (e) => {
  showError(e.reason?.message || 'Unknown Promise Rejection', null);
});
