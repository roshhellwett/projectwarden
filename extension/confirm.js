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
