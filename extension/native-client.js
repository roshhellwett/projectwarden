class NativeClient {
  constructor() {
    this.port = null;
    this.pending = {};
  }

  connect() {
    try {
      this.port = chrome.runtime.connectNative('com.zenith.passkeys');
      this.port.onMessage.addListener(msg => this._handleMessage(msg));
      this.port.onDisconnect.addListener(() => {
        this.port = null;
      });
      return true;
    } catch (e) {
      console.warn('Native connect failed:', e);
      return false;
    }
  }

  _handleMessage(msg) {
    const reqId = msg.requestId;
    if (reqId !== undefined && this.pending[reqId]) {
      this.pending[reqId](msg);
      delete this.pending[reqId];
    }
  }

  send(action, data = {}) {
    return new Promise((resolve, reject) => {
      if (!this.port) {
        reject(new Error('Native host not connected'));
        return;
      }
      const requestId = Date.now() + Math.random();
      this.pending[requestId] = resolve;
      this.port.postMessage({ requestId, action, ...data });
      setTimeout(() => {
        if (this.pending[requestId]) {
          delete this.pending[requestId];
          reject(new Error('Timeout'));
        }
      }, 30000);
    });
  }

  disconnect() {
    if (this.port) {
      this.port.disconnect();
      this.port = null;
    }
  }
}
