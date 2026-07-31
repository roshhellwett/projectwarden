class CborEncoder {
  encode(value) { return this._encode(value); }

  _encode(value) {
    if (value === null) return this._encodeUint(22, 7);
    if (value === true) return this._encodeUint(21, 7);
    if (value === false) return this._encodeUint(20, 7);
    if (typeof value === 'number') {
      if (Number.isInteger(value) && value >= 0) return this._encodeUint(value, 0);
      if (Number.isInteger(value) && value < 0) return this._encodeUint(-1 - value, 1);
      return this._encodeFloat(value);
    }
    if (typeof value === 'string') {
      const bytes = new TextEncoder().encode(value);
      return this._encodeUint(bytes.length, 3) + new Uint8Array(bytes).buffer;
    }
    if (value instanceof Uint8Array) return this._encodeUint(value.length, 2) + value.buffer;
    if (Array.isArray(value)) {
      const parts = [this._encodeUint(value.length, 4)];
      value.forEach(v => parts.push(this._encode(v)));
      return this._concat(parts);
    }
    if (typeof value === 'object') {
      const keys = Object.keys(value);
      const parts = [this._encodeUint(keys.length, 5)];
      keys.forEach(k => { parts.push(this._encode(k)); parts.push(this._encode(value[k])); });
      return this._concat(parts);
    }
    throw new Error('Cannot encode ' + typeof value);
  }

  _encodeUint(value, major) {
    const header = major << 5;
    if (value < 24) return new Uint8Array([header | value]).buffer;
    if (value < 256) return new Uint8Array([header | 24, value]).buffer;
    if (value < 65536) { const b = new ArrayBuffer(3); const v = new DataView(b); v.setUint8(0, header | 25); v.setUint16(1, value); return b; }
    const b = new ArrayBuffer(5); const v = new DataView(b); v.setUint8(0, header | 26); v.setUint32(1, value); return b;
  }

  _encodeFloat(value) {
    const b = new ArrayBuffer(9); const v = new DataView(b); v.setUint8(0, 251); v.setFloat64(1, value); return b;
  }

  _concat(parts) {
    const total = parts.reduce((s, p) => s + p.byteLength, 0);
    const result = new Uint8Array(total);
    let offset = 0;
    parts.forEach(p => { result.set(new Uint8Array(p), offset); offset += p.byteLength; });
    return result.buffer;
  }
}

class CborDecoder {
  decode(buffer) {
    this._view = new DataView(buffer);
    this._offset = 0;
    return this._decode();
  }

  _decode() {
    const first = this._view.getUint8(this._offset++);
    const major = first >> 5;
    const info = first & 0x1f;
    const value = this._readExtra(info);
    switch (major) {
      case 0: return value;
      case 1: return -1 - value;
      case 2: return new Uint8Array(this._view.buffer, this._view.byteOffset + this._offset, value);
      case 3: {
        const bytes = new Uint8Array(this._view.buffer, this._view.byteOffset + this._offset, value);
        this._offset += value;
        return new TextDecoder().decode(bytes);
      }
      case 4: { const arr = []; for (let i = 0; i < value; i++) arr.push(this._decode()); return arr; }
      case 5: { const obj = {}; for (let i = 0; i < value; i++) { const k = this._decode(); obj[k] = this._decode(); } return obj; }
      case 7: {
        if (value === 20) return false;
        if (value === 21) return true;
        if (value === 22) return null;
        if (value === 25) {
          const half = this._view.getUint16(this._offset - 2);
          return this._halfToFloat(half);
        }
        if (value === 26) return this._view.getFloat32(this._offset - 4);
        if (value === 27) return this._view.getFloat64(this._offset - 8);
        return value;
      }
      default: throw new Error('Unknown major type: ' + major);
    }
  }

  _readExtra(info) {
    if (info < 24) return info;
    if (info === 24) return this._view.getUint8(this._offset++);
    if (info === 25) { const v = this._view.getUint16(this._offset); this._offset += 2; return v; }
    if (info === 26) { const v = this._view.getUint32(this._offset); this._offset += 4; return v; }
    if (info === 27) {
      const hi = this._view.getUint32(this._offset);
      const lo = this._view.getUint32(this._offset + 4);
      this._offset += 8;
      return hi * 4294967296 + lo;
    }
    throw new Error('Unsupported extra: ' + info);
  }

  _halfToFloat(half) {
    const sign = (half >> 15) & 0x01;
    const exp = (half >> 10) & 0x1f;
    const mant = half & 0x3ff;
    if (exp === 0) return (sign ? -1 : 1) * Math.pow(2, -14) * (mant / 1024);
    if (exp === 31) return mant ? NaN : (sign ? -Infinity : Infinity);
    return (sign ? -1 : 1) * Math.pow(2, exp - 15) * (1 + mant / 1024);
  }
}
