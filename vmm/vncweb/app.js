import {RFB, keySym} from './client.js';

const canvas = document.querySelector('#screen');
const context = canvas.getContext('2d');
const status = document.querySelector('#status');
const button = document.querySelector('#connect');
const cad = document.querySelector('#cad');
const token = location.hash.slice(1) || sessionStorage.getItem('trex-vnc-token');
if (token) sessionStorage.setItem('trex-vnc-token', token);
history.replaceState(null, '', location.pathname);

let socket, rfb, active = false, buttons = 0;
let x = 32768, y = 32768;
const held = new Set();
const buttonMask = button => [1, 2, 4][button] || 0;

function release() {
  if (active) {
    for (const key of held) rfb.key(key, false);
    rfb.pointer(x, y, 0);
  }
  held.clear();
  buttons = 0;
}

function stop() {
  release();
  active = false;
  cad.disabled = true;
  rfb?.close();
  socket?.close();
  button.textContent = 'Connect';
  if (document.pointerLockElement === canvas) document.exitPointerLock();
}

function draw(x, y, width, height, pixels) {
  const rgba = new Uint8ClampedArray(pixels.buffer, pixels.byteOffset, pixels.length);
  context.putImageData(new ImageData(rgba, width, height), x, y);
}

function connect() {
  if (socket && socket.readyState < WebSocket.CLOSING) {
    stop();
    return;
  }
  if (!token) {
    status.textContent = 'Open the complete session URL printed by trex.';
    return;
  }
  status.textContent = 'Connecting…';
  button.textContent = 'Disconnect';
  const scheme = location.protocol === 'https:' ? 'wss' : 'ws';
  const ws = new WebSocket(`${scheme}://${location.host}/rfb?token=${encodeURIComponent(token)}`);
  socket = ws;
  ws.binaryType = 'arraybuffer';
  const client = new RFB(
    bytes => { if (ws.readyState === WebSocket.OPEN) ws.send(bytes); },
    draw,
    (width, height) => { canvas.width = width; canvas.height = height; },
    () => {
      active = true;
      cad.disabled = false;
      status.textContent = 'Connected';
      client.pointer(x, y, 0);
    },
  );
  rfb = client;
  ws.onmessage = event => {
    if (socket !== ws) return;
    try {
      client.feed(new Uint8Array(event.data));
    } catch (error) {
      status.textContent = error.message;
      stop();
    }
  };
  ws.onerror = () => {
    if (socket === ws) {
      status.textContent = 'Connection failed. Check the session URL and whether another browser is connected.';
    }
  };
  ws.onclose = () => {
    client.close();
    if (socket !== ws) return;
    held.clear();
    buttons = 0;
    active = false;
    cad.disabled = true;
    button.textContent = 'Connect';
    if (status.textContent === 'Connected') status.textContent = 'Disconnected';
  };
}

function keyEvent(event, down) {
  if (!active) return;
  const key = keySym(event.code);
  if (!key) return;
  event.preventDefault();
  if (down) held.add(key);
  else held.delete(key);
  rfb.key(key, down);
}

button.onclick = connect;
canvas.onmousedown = event => {
  if (!active) return;
  event.preventDefault();
  canvas.focus();
  if (document.pointerLockElement !== canvas) {
    canvas.requestPointerLock();
    return;
  }
  buttons |= buttonMask(event.button);
  rfb.pointer(x, y, buttons);
};
window.addEventListener('mouseup', event => {
  if (!active) return;
  buttons &= ~buttonMask(event.button);
  rfb.pointer(x, y, buttons);
});
canvas.onmousemove = event => {
  if (!active || document.pointerLockElement !== canvas) return;
  // Accumulate relative motion modulo the RFB coordinate width. The server
  // unwraps each difference before delivering it to the guest's PS/2 mouse.
  x = (x + event.movementX) & 65535;
  y = (y + event.movementY) & 65535;
  rfb.pointer(x, y, buttons);
};
canvas.oncontextmenu = event => event.preventDefault();
canvas.onkeydown = event => keyEvent(event, true);
canvas.onkeyup = event => keyEvent(event, false);
canvas.onblur = release;
window.addEventListener('blur', release);
document.addEventListener('pointerlockchange', () => {
  if (document.pointerLockElement !== canvas) release();
});
cad.onclick = () => {
  if (!active) return;
  release();
  for (const key of [0xffe3, 0xffe9, 0xffff]) {
    held.add(key);
    rfb.key(key, true);
  }
  setTimeout(release, 100);
};
if (token) connect();
