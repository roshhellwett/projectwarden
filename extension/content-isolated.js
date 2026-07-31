(function () {
  const PREFIX = '__zenith_passkeys__';

  window.addEventListener('message', async (event) => {
    if (event.source !== window) return;
    if (!event.data || event.data.type !== PREFIX + '_request') return;

    const { requestId, action, options } = event.data;
    const origin = window.location.origin;

    try {
      const result = await chrome.runtime.sendMessage({
        action: action === 'create' ? 'webauthn_create' : 'webauthn_get',
        options,
        origin,
      });

      window.postMessage({
        type: PREFIX + '_response',
        requestId,
        result,
      }, '*');
    } catch (err) {
      window.postMessage({
        type: PREFIX + '_response',
        requestId,
        error: err.message,
      }, '*');
    }
  });
})();
