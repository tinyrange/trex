import {RFB, keySym} from './client.js';

const canvas = document.querySelector('#screen');
const context = canvas.getContext('2d');
const status = document.querySelector('#status');
const button = document.querySelector('#connect');
const cad = document.querySelector('#cad');
const tabs = document.querySelector('#tabs');
const create = document.querySelector('#create');
const title = document.querySelector('#vm-name');
const token = location.hash.slice(1) || sessionStorage.getItem('trex-vnc-token');
if (token) sessionStorage.setItem('trex-vnc-token', token);
history.replaceState(null, '', location.pathname);

let socket, rfb, active = false, buttons = 0;
let selected, machines = [], creating = false, cadTimer;
let x = 32768, y = 32768;
let absolute = false;
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
  clearTimeout(cadTimer);
  release();
  active = false;
  cad.disabled = true;
  rfb?.close();
  socket?.close();
  socket = null;
  absolute = false;
  canvas.style.cursor = '';
  x = y = 32768;
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
  if (!selected) return;
  absolute = false;
  x = y = 32768;
  canvas.style.cursor = '';
  const ws = new WebSocket(`${scheme}://${location.host}/rfb?token=${encodeURIComponent(token)}&vm=${encodeURIComponent(selected)}`);
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
    absolute = false;
    canvas.style.cursor = '';
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
cad.onclick = () => {
  if (!active) return;
  release();
  for (const key of [0xffe3, 0xffe9, 0xffff]) {
    held.add(key);
    rfb.key(key, true);
  }
  cadTimer = setTimeout(release, 100);
};

function renderTabs() {
  tabs.replaceChildren(...machines.map(vm => {
    const tab = document.createElement('button');
    tab.textContent = vm.name;
    tab.setAttribute('role', 'tab');
    tab.setAttribute('aria-selected', String(vm.id === selected));
    tab.onclick = () => select(vm.id);
    return tab;
  }));
}
function select(id) {
  if (id === selected) return;
  stop();
  selected = id;
  sessionStorage.setItem('trex-vnc-vm', id);
  title.textContent = machines.find(vm => vm.id === id)?.name || 'VM';
  context.clearRect(0, 0, canvas.width, canvas.height);
  renderTabs();
  connect();
}
async function api(method = 'GET') {
  const response = await fetch('/api/vms', {method, headers: {Authorization: `Bearer ${token}`}});
  if (!response.ok) throw new Error((await response.text()).trim());
  return response.json();
}
async function refresh() {
  const result = await api();
  machines = result.vms;
  create.hidden = !result.canCreate;
  create.disabled = creating || result.creating;
  renderTabs();
  return result;
}
create.onclick = async () => {
  if (creating) return;
  creating = true;
  create.disabled = true;
  create.textContent = 'Creating VM…';
  try {
    const vm = await api('POST');
    await refresh();
    select(vm.id);
  } catch (error) {
    status.textContent = `Could not create VM: ${error.message}`;
  } finally {
    creating = false;
    create.disabled = false;
    create.textContent = '+ New VM';
  }
};
if (token) {
  refresh().then(() => {
    const previous = sessionStorage.getItem('trex-vnc-vm');
    select(machines.some(vm => vm.id === previous) ? previous : machines[0]?.id);
  }).catch(error => { status.textContent = error.message; });
}
window.addEventListener('focus', () => {
  if (token) refresh().catch(error => { status.textContent = error.message; });
});
