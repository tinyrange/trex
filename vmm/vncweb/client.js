// RFB 3.8 protocol client, independent of the DOM and WebSocket transport.
// Wire integers are big endian; negotiated pixel words are little-endian RGB.
const VERSION = 'RFB 003.008\n';
const MAX_BUFFER = 70 * 1024 * 1024;
const DESKTOP_SIZE = -223;

export class RFB {
  constructor(send, frame, resize, ready) {
    Object.assign(this, {send, frame, resize, ready});
    this.buffer = new Uint8Array();
    this.state = 'version';
    this.rectangles = 0;
  }

  feed(data) {
    if (this.buffer.length + data.length > MAX_BUFFER) {
      throw Error('RFB receive limit exceeded');
    }
    const joined = new Uint8Array(this.buffer.length + data.length);
    joined.set(this.buffer);
    joined.set(data, this.buffer.length);
    this.buffer = joined;
    while (this.parse()) {}
  }

  take(n) {
    const bytes = this.buffer.slice(0, n);
    this.buffer = this.buffer.subarray(n);
    return bytes;
  }

  parse() {
    const bytes = this.buffer;
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    switch (this.state) {
      case 'version':
        if (bytes.length < 12) return false;
        if (new TextDecoder().decode(this.take(12)) !== VERSION) {
          throw Error('RFB 3.8 required');
        }
        this.send(new TextEncoder().encode(VERSION));
        this.state = 'security';
        break;
      case 'security':
        if (!bytes.length) return false;
        if (!bytes[0]) throw Error('Server rejected connection');
        if (bytes.length < 1 + bytes[0]) return false;
        if (!this.take(1 + bytes[0]).subarray(1).includes(1)) {
          throw Error('Unsupported RFB authentication');
        }
        this.send(Uint8Array.of(1));
        this.state = 'result';
        break;
      case 'result':
        if (bytes.length < 4) return false;
        if (view.getUint32(0)) throw Error('RFB authentication failed');
        this.take(4);
        this.send(Uint8Array.of(1));
        this.state = 'init';
        break;
      case 'init':
        return this.initialize(view);
      case 'message':
        return this.message(view);
      case 'rectangle':
        return this.rectangle(view);
      default:
        throw Error('Invalid RFB parser state');
    }
    return true;
  }

  initialize(view) {
    if (view.byteLength < 24) return false;
    const nameLength = view.getUint32(20);
    if (nameLength > 65536) throw Error('Server name too long');
    if (view.byteLength < 24 + nameLength) return false;
    this.size(view.getUint16(0), view.getUint16(2));
    this.take(24 + nameLength);
    // SetPixelFormat: RGB888 in 32-bit little-endian words.
    this.send(Uint8Array.of(0, 0, 0, 0, 32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 0, 8, 16, 0, 0, 0));
    // SetEncodings: raw pixels and DesktopSize.
    this.send(Uint8Array.of(2, 0, 0, 2, 0, 0, 0, 0, 255, 255, 255, 33));
    this.state = 'message';
    this.ready();
    this.request(false);
    return true;
  }

  message(view) {
    if (!view.byteLength) return false;
    if (view.getUint8(0) === 2) { // Bell has no payload.
      this.take(1);
      return true;
    }
    if (view.getUint8(0) !== 0) throw Error('Unsupported server message');
    if (view.byteLength < 4) return false;
    this.rectangles = view.getUint16(2);
    this.take(4);
    this.state = this.rectangles ? 'rectangle' : 'message';
    if (!this.rectangles) this.next();
    return true;
  }

  rectangle(view) {
    if (view.byteLength < 12) return false;
    const x = view.getUint16(0), y = view.getUint16(2);
    const width = view.getUint16(4), height = view.getUint16(6);
    const encoding = view.getInt32(8);
    if (encoding === DESKTOP_SIZE) {
      this.take(12);
      this.size(width, height);
    } else {
      if (encoding !== 0 || !width || !height ||
          x + width > this.width || y + height > this.height) {
        throw Error('Invalid RFB rectangle');
      }
      const count = width * height * 4;
      if (view.byteLength < 12 + count) return false;
      this.take(12);
      const pixels = this.take(count);
      for (let i = 3; i < count; i += 4) pixels[i] = 255;
      this.frame(x, y, width, height, pixels);
    }
    if (--this.rectangles === 0) {
      this.state = 'message';
      this.next();
    }
    return true;
  }

  size(width, height) {
    if (!width || !height || width > 4096 || height > 4096) {
      throw Error('Invalid display dimensions');
    }
    this.width = width;
    this.height = height;
    this.resize(width, height);
  }

  next() {
    clearTimeout(this.timer);
    this.timer = setTimeout(() => this.request(true), 50);
  }

  close() {
    clearTimeout(this.timer);
  }

  request(incremental) {
    const bytes = new Uint8Array(10), view = new DataView(bytes.buffer);
    bytes[0] = 3;
    bytes[1] = +incremental;
    view.setUint16(6, this.width);
    view.setUint16(8, this.height);
    this.send(bytes);
  }

  key(key, down) {
    const bytes = new Uint8Array(8);
    bytes[0] = 4;
    bytes[1] = +down;
    new DataView(bytes.buffer).setUint32(4, key);
    this.send(bytes);
  }

  pointer(x, y, buttons) {
    const bytes = new Uint8Array(6), view = new DataView(bytes.buffer);
    bytes[0] = 5;
    bytes[1] = buttons;
    view.setUint16(2, x);
    view.setUint16(4, y);
    this.send(bytes);
  }
}

const KEY_SYMS = {
  Escape: 0xff1b, Backspace: 0xff08, Tab: 0xff09, Enter: 0xff0d, Space: 32,
  ShiftLeft: 0xffe1, ShiftRight: 0xffe2, ControlLeft: 0xffe3, ControlRight: 0xffe4,
  AltLeft: 0xffe9, AltRight: 0xffea, CapsLock: 0xffe5,
  Delete: 0xffff, Insert: 0xff63, Home: 0xff50, End: 0xff57,
  PageUp: 0xff55, PageDown: 0xff56,
  ArrowLeft: 0xff51, ArrowUp: 0xff52, ArrowRight: 0xff53, ArrowDown: 0xff54,
  Minus: 45, Equal: 61, BracketLeft: 91, BracketRight: 93,
  Semicolon: 59, Quote: 39, Backquote: 96, Backslash: 92,
  Comma: 44, Period: 46, Slash: 47,
};

export function keySym(code) {
  if (/^Key[A-Z]$/.test(code)) return code.charCodeAt(3) + 32;
  if (/^Digit[0-9]$/.test(code)) return code.charCodeAt(5);
  if (/^F([1-9]|1[0-2])$/.test(code)) return 0xffbd + Number(code.slice(1));
  return KEY_SYMS[code];
}
