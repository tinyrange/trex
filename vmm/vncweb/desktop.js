import {RFB, keySym} from './client.js';

const canvas = document.querySelector('#screen');
const context = canvas.getContext('2d');
let socket, rfb, active = false, absolute = false, buttons = 0;
let x = 32768, y = 32768, retry, closed = false;
const held = new Set();
const buttonMask = button => [1, 2, 4][button] || 0;
function fit() {
  const scale = Math.min(window.innerWidth / canvas.width, window.innerHeight / canvas.height);
  canvas.style.width = `${canvas.width * scale}px`;
  canvas.style.height = `${canvas.height * scale}px`;
}
window.addEventListener('resize', fit);
function release() {
  if (active) {
    for (const key of held) rfb.key(key, false);
    rfb.pointer(x, y, 0);
  }
  held.clear();
  buttons = 0;
}
function keyEvent(event, down) {
  if (!active) return;
  const key = keySym(event.code);
  if (!key) return;
  event.preventDefault();
  if (down) held.add(key); else held.delete(key);
  rfb.key(key, down);
}
function connect() {
  if (closed) return;
  // Relative to the page, not the origin root: works under /node/ and /rnode/.
  const url = new URL('./rfb', location.href);
  url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:';
  const ws = new WebSocket(url);
  socket = ws;
  ws.binaryType = 'arraybuffer';
  const client = new RFB(
    bytes => { if (ws.readyState === WebSocket.OPEN) ws.send(bytes); },
    (x, y, width, height, pixels) => {
      context.putImageData(new ImageData(new Uint8ClampedArray(pixels.buffer, pixels.byteOffset, pixels.length), width, height), x, y);
    },
    (width, height) => { canvas.width = width; canvas.height = height; fit(); },
    () => { active = true; canvas.focus(); client.pointer(x, y, 0); },
    mode => {
      absolute = mode;
      x = y = mode ? 0 : 32768;
      buttons = 0;
      canvas.style.cursor = mode ? 'none' : '';
      if (!mode) client.pointer(x, y, 0);
      if (mode && document.pointerLockElement === canvas) document.exitPointerLock();
    },
  );
  rfb = client;
  ws.onmessage = event => {
    if (socket !== ws) return;
    try { client.feed(new Uint8Array(event.data)); }
    catch (error) { console.error('Desktop protocol error', error); ws.close(); }
  };
  ws.onclose = () => {
    client.close();
    if (socket !== ws) return;
    held.clear(); buttons = 0; active = false; absolute = false;
    x = y = 32768;
    canvas.style.cursor = '';
    if (document.pointerLockElement === canvas) document.exitPointerLock();
    // Also covers the interval while the VM is being constructed. No UI chrome.
    if (!closed) retry = setTimeout(connect, 1500);
  };
}
function position(event) {
  const rect = canvas.getBoundingClientRect();
  x = Math.max(0, Math.min(canvas.width - 1, Math.floor((event.clientX - rect.left) * canvas.width / rect.width)));
  y = Math.max(0, Math.min(canvas.height - 1, Math.floor((event.clientY - rect.top) * canvas.height / rect.height)));
}
canvas.onmousedown = event => {
  if (!active) return;
  event.preventDefault();
  canvas.focus();
  if (absolute) position(event);
  else if (document.pointerLockElement !== canvas) {
    canvas.requestPointerLock();
    return;
  }
  buttons |= buttonMask(event.button);
  rfb.pointer(x, y, buttons);
};
window.addEventListener('mouseup', event => {
  if (!active || !(buttons & buttonMask(event.button))) return;
  if (absolute) position(event);
  buttons &= ~buttonMask(event.button);
  rfb.pointer(x, y, buttons);
});
canvas.onmousemove = event => {
  if (!active) return;
  if (absolute) {
    position(event);
    rfb.pointer(x, y, buttons);
    return;
  }
  if (document.pointerLockElement !== canvas) return;
  // Accumulate relative motion modulo the RFB coordinate width. The server
  // unwraps each difference before delivering it to the guest's PS/2 mouse.
  x = (x + event.movementX) & 65535;
  y = (y + event.movementY) & 65535;
  rfb.pointer(x, y, buttons);
};
canvas.addEventListener('wheel', event => {
  if (!active || !absolute) return;
  event.preventDefault();
  if (absolute) position(event);
  if (event.deltaY) {
    rfb.pointer(x, y, buttons | (event.deltaY < 0 ? 8 : 16));
    rfb.pointer(x, y, buttons);
  }
}, {passive: false});
canvas.oncontextmenu = event => event.preventDefault();
canvas.onkeydown = event => keyEvent(event, true);
canvas.onkeyup = event => keyEvent(event, false);
canvas.onblur = release;
window.addEventListener('blur', release);
document.addEventListener('pointerlockchange', () => {
  if (document.pointerLockElement !== canvas) release();
});

window.addEventListener('pagehide', () => {
  closed = true;
  clearTimeout(retry);
  release();
  rfb?.close();
  socket?.close();
});
window.addEventListener('pageshow', event => {
  if (event.persisted) { closed = false; connect(); }
});
fit();
connect();
