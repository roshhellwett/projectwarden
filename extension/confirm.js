const params = new URLSearchParams(location.search);
const action = params.get('action');
const origin = params.get('origin');
const confirmId = params.get('confirmId');

document.getElementById('origin').textContent = origin || 'Unknown';
document.getElementById('action').textContent = action === 'create' ? 'Register new passkey' : 'Sign in with passkey';
document.getElementById('username').textContent = action === 'create' ? 'New credential will be created' : '';

function allow() {
  chrome.runtime.sendMessage({ action: 'confirm_response', confirmId, allowed: true });
  window.close();
}

function deny() {
  chrome.runtime.sendMessage({ action: 'confirm_response', confirmId, allowed: false });
  window.close();
}

document.getElementById('btn-allow').addEventListener('click', allow);
document.getElementById('btn-deny').addEventListener('click', deny);

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
