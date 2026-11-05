// RFB 3.8 protocol client, independent of the DOM and WebSocket transport.
// Wire integers are big endian; negotiated pixel words are little-endian RGB.
const VERSION = 'RFB 003.008\n';
const MAX_BUFFER = 70 * 1024 * 1024;
const DESKTOP_SIZE = -223;
const EXTENDED_DESKTOP_SIZE = -308;
const POINTER_TYPE = -257;

// The current shared Windows framebuffer reserves 8 MiB. Keep viewport-driven
// requests within its 1080p limit; wire-level requests remain exact dimensions.
const MAX_VIEWPORT_WIDTH = 1920, MAX_VIEWPORT_HEIGHT = 1080;
export function viewportSize(width, height) {
  if (width > MAX_VIEWPORT_WIDTH && width * MAX_VIEWPORT_HEIGHT >= height * MAX_VIEWPORT_WIDTH) {
    height = height * MAX_VIEWPORT_WIDTH / width;
    width = MAX_VIEWPORT_WIDTH;
  } else if (height > MAX_VIEWPORT_HEIGHT) {
    width = width * MAX_VIEWPORT_HEIGHT / height;
    height = MAX_VIEWPORT_HEIGHT;
  }
  return [Math.max(1, Math.floor(width)), Math.max(1, Math.floor(height))];
}

export class RFB {
  constructor(send, frame, resize, ready, pointerMode = () => {}) {
    Object.assign(this, {send, frame, resize, ready, pointerMode});
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
    // Raw pixels, DesktopSize, ExtendedDesktopSize, QEMU Pointer Motion Change.
    this.send(Uint8Array.of(2, 0, 0, 4, 0, 0, 0, 0, 255, 255, 255, 33, 255, 255, 254, 204, 255, 255, 254, 255));
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
    if (encoding === POINTER_TYPE) {
      if (x > 1) throw Error('Invalid pointer mode');
      this.take(12);
      this.relative = x === 0;
      this.pointerX = this.pointerY = undefined;
      this.pointerMode(x === 1);
    } else if (encoding === EXTENDED_DESKTOP_SIZE) {
      if (view.byteLength < 16) return false;
      const count = view.getUint8(12), length = 16 + count * 16;
      if (view.byteLength < length) return false;
      if (x > 2) throw Error('Invalid desktop resize reason');
      // A rejected request does not change the framebuffer or screen layout.
      if (x !== 1 || y === 0) {
        if (!count) throw Error('Invalid desktop screen layout');
        this.canResize = count === 1 && view.getUint16(20) === 0 && view.getUint16(22) === 0 &&
          view.getUint16(24) === width && view.getUint16(26) === height;
        this.screenID = view.getUint32(16);
        this.screenFlags = view.getUint32(28);
        this.size(width, height);
      }
      if (x === 1) this.pendingResize = null;
      this.take(length);
      this.scheduleResize();
    } else if (encoding === DESKTOP_SIZE) {
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
    clearTimeout(this.resizeTimer);
    this.closed = true;
  }

  // Latest viewport wins. Requests wait for server capability advertisement,
  // are debounced, and a rejected size is not retried until the viewport changes.
  requestResize(width, height, delay = 200) {
    if (!Number.isFinite(width) || !Number.isFinite(height) || width < 1 || height < 1) return;
    this.desiredResize = viewportSize(width, height);
    this.scheduleResize(delay);
  }

  scheduleResize(delay = 200) {
    clearTimeout(this.resizeTimer);
    if (this.closed || !this.canResize || this.pendingResize || !this.desiredResize) return;
    this.resizeTimer = setTimeout(() => this.sendResize(), delay);
  }

  sendResize() {
    if (this.closed || !this.canResize || this.pendingResize || !this.desiredResize) return;
    const [width, height] = this.desiredResize;
    const key = `${width}x${height}`;
    if (key === this.lastResize || (width === this.width && height === this.height)) return;
    const bytes = new Uint8Array(24), view = new DataView(bytes.buffer);
    bytes[0] = 251;
    view.setUint16(2, width); view.setUint16(4, height); bytes[6] = 1;
    view.setUint32(8, this.screenID);
    view.setUint16(16, width); view.setUint16(18, height);
    view.setUint32(20, this.screenFlags);
    this.lastResize = this.pendingResize = key;
    this.send(bytes);
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
    const previousX = this.pointerX, previousY = this.pointerY;
    this.pointerX = x;
    this.pointerY = y;
    if (this.relative) {
      const delta = (value, previous) => previous === undefined ? 0 : ((value - previous + 32768) & 65535) - 32768;
      x = 32767 + Math.max(-32767, delta(x, previousX));
      y = 32767 + Math.max(-32767, delta(y, previousY));
    }
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
