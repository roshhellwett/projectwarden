(function () {
  const PREFIX = '__zenith_passkeys__';

  window.addEventListener('message', async (event) => {
    if (event.source !== window) return;
    if (!event.data) return;

    if (event.data.type === PREFIX + '_get_candidates') {
      const { requestId, rpId } = event.data;
      try {
        const result = await chrome.runtime.sendMessage({
          action: 'webauthn_query_candidates',
          rpId,
          origin: window.location.origin,
        });
        window.postMessage({
          type: PREFIX + '_get_candidates_response',
          requestId,
          candidates: (result && result.candidates) || [],
        }, window.location.origin);
      } catch (err) {
        window.postMessage({
          type: PREFIX + '_get_candidates_response',
          requestId,
          candidates: [],
        }, window.location.origin);
      }
      return;
    }

    if (event.data.type !== PREFIX + '_request') return;

    const { requestId, action, options } = event.data;
    // SECURITY: use THIS frame's origin — never trust an origin field in the
    // message itself (a page could claim any origin).
    const origin = window.location.origin;

    try {
      const result = await chrome.runtime.sendMessage({
        action: action === 'create' ? 'webauthn_create' : 'webauthn_get',
        options,
        origin,
      });

      if (result && result.error) {
        window.postMessage({
          type: PREFIX + '_response',
          requestId,
          error: result.error,
        }, window.location.origin);
        return;
      }

      window.postMessage({
        type: PREFIX + '_response',
        requestId,
        result,
      }, window.location.origin);
    } catch (err) {
      window.postMessage({
        type: PREFIX + '_response',
        requestId,
        error: err.message,
      }, window.location.origin);
    }
  });
})();
