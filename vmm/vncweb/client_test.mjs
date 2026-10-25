import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
const source = await readFile(new URL('./client.js', import.meta.url), 'utf8');
const {RFB, keySym, viewportSize} = await import('data:text/javascript;base64,' + Buffer.from(source).toString('base64'));
function fixture() {
  const sent = [], frames = [], sizes = [], modes = [];
  let ready = 0;
  const client = new RFB(b => sent.push([...b]), (...a) => frames.push(a), (...a) => sizes.push(a), () => ready++, b => modes.push(b));
  return {client, sent, frames, sizes, modes, ready: () => ready};
}
function init(client) {
  const bytes = Buffer.alloc(24); bytes.writeUInt16BE(2); bytes.writeUInt16BE(2, 2);
  const wire = Buffer.concat([Buffer.from('RFB 003.008\n'), Buffer.from([1, 1, 0, 0, 0, 0]), bytes]);
  for (const byte of wire) client.feed(Uint8Array.of(byte));
}
function rectangle(encoding, x, y, w, h, pixels = []) {
  const b = Buffer.alloc(16 + pixels.length); b.writeUInt16BE(1, 2);
  b.writeUInt16BE(x, 4); b.writeUInt16BE(y, 6); b.writeUInt16BE(w, 8); b.writeUInt16BE(h, 10);
  b.writeInt32BE(encoding, 12); b.set(pixels, 16); return b;
}
test('fragmented handshake, raw rectangles, resizing and pointer negotiation', () => {
  const f = fixture(); init(f.client);
  assert.equal(f.ready(), 1); assert.deepEqual(f.sizes, [[2, 2]]);
  assert.deepEqual(f.sent.at(-1), [3, 0, 0, 0, 0, 0, 0, 2, 0, 2]);
  const pixels = rectangle(0, 1, 0, 1, 1, [12, 34, 56, 0]);
  f.client.feed(pixels.subarray(0, 18)); assert.equal(f.frames.length, 0);
  f.client.feed(pixels.subarray(18));
  assert.deepEqual(f.frames[0].slice(0, 4), [1, 0, 1, 1]);
  assert.deepEqual([...f.frames[0][4]], [12, 34, 56, 255]);
  f.client.feed(rectangle(-223, 0, 0, 3, 4)); assert.deepEqual(f.sizes.at(-1), [3, 4]);
  f.client.feed(rectangle(-257, 0, 0, 0, 0));
  f.client.pointer(65535, 0, 1); f.client.pointer(0, 65535, 0);
  assert.deepEqual(f.sent.at(-1), [5, 0, 128, 0, 127, 254]);
  f.client.feed(rectangle(-257, 1, 0, 0, 0)); f.client.pointer(2, 3, 4);
  assert.deepEqual(f.sent.at(-1), [5, 4, 0, 2, 0, 3]); assert.deepEqual(f.modes, [false, true]);
  f.client.key(0xffe3, false); assert.deepEqual(f.sent.at(-1), [4, 0, 0, 0, 0, 0, 255, 227]);
  f.client.close();
});
test('reject malformed protocol and out-of-display rectangles', () => {
  assert.throws(() => fixture().client.feed(Buffer.from('RFB 003.007\n')), /3.8/);
  for (const bad of [rectangle(0, 2, 0, 1, 1), rectangle(0, 0, 0, 0, 1), rectangle(-257, 2, 0, 0, 0), rectangle(-223, 0, 0, 4097, 1)]) {
    const f = fixture(); init(f.client); assert.throws(() => f.client.feed(bad), /Invalid/); f.client.close();
  }
  assert.equal(keySym('KeyA'), 97); assert.equal(keySym('F12'), 0xffc9);
  assert.equal(keySym('ControlRight'), 0xffe4); assert.equal(keySym('Unidentified'), undefined);
});

test('fragmented handshake, raw pixels, resize and input',()=>{
 const sent=[],frames=[],sizes=[];
 const c=new RFB(b=>sent.push(b),(x,y,w,h,p)=>frames.push([...p]),(w,h)=>sizes.push([w,h]),()=>{});
 const feed=b=>{for(const byte of b)c.feed(Uint8Array.of(byte));};
 feed(new TextEncoder().encode('RFB 003.008\n'));feed([1,1]);feed([0,0,0,0]);
 const init=new Uint8Array(24);init[1]=2;init[3]=1;feed(init);
 feed([0,0,0,1,0,0,0,0,0,2,0,1,0,0,0,0,1,2,3,0,4,5,6,0]);
 assert.deepEqual(frames,[[1,2,3,255,4,5,6,255]]);
 feed([0,0,0,1,0,0,0,0,0,4,0,3,255,255,255,33]);assert.deepEqual(sizes,[[2,1],[4,3]]);
 c.key(keySym('KeyA'),true);assert.deepEqual([...sent.at(-1)],[4,1,0,0,0,0,0,97]);c.close();
});
test('rejects bad version and dimensions',()=>{
 const c=new RFB(()=>{},()=>{},()=>{},()=>{});
 assert.throws(()=>c.feed(new TextEncoder().encode('RFB 003.003\n')));
 assert.throws(()=>c.size(65535,65535));
});
test('pointer mode notifications can change without pixels',()=>{
 const modes=[];
 const c=new RFB(()=>{},()=>{},()=>{},()=>{},mode=>modes.push(mode));
 c.state='message';c.width=1280;c.height=720;
 for(const mode of [1,0,1]) {
  for(const byte of [0,0,0,1,0,mode,0,0,5,0,2,208,255,255,254,255]) c.feed(Uint8Array.of(byte));
 }
 assert.deepEqual(modes,[true,false,true]);c.close();
});
test('negotiated relative motion uses biased deltas and stationary button changes',()=>{
 const sent=[];
 const c=new RFB(b=>sent.push([...b]),()=>{},()=>{},()=>{});
 c.state='message';c.width=c.height=2;
 c.feed(Uint8Array.from([0,0,0,1,0,0,0,0,0,2,0,2,255,255,254,255]));
 c.pointer(65534,100,0);
 c.pointer(3,97,1);
 assert.deepEqual(sent.at(-1),[5,1,128,4,127,252]);
 c.pointer(3,97,0);
 assert.deepEqual(sent.at(-1),[5,0,127,255,127,255]);c.close();
});

function extendedSize(width, height, reason = 0, status = 0) {
  const layout = Buffer.alloc(20); layout[0] = 1;
  layout.writeUInt32BE(17, 4);
  layout.writeUInt16BE(width, 12); layout.writeUInt16BE(height, 14);
  layout.writeUInt32BE(0x10203040, 16);
  return rectangle(-308, reason, status, width, height, layout);
}
const pause = () => new Promise(resolve => setTimeout(resolve, 10));

test('resize waits for capability, preserves layout and waits for applied geometry', async () => {
  const f = fixture(); init(f.client);
  f.client.requestResize(800, 600, 0); await pause();
  assert.equal(f.sent.filter(b => b[0] === 251).length, 0);
  for (const byte of extendedSize(2, 2)) f.client.feed(Uint8Array.of(byte));
  f.client.scheduleResize(0); await pause();
  const request = Buffer.from(f.sent.find(b => b[0] === 251));
  assert.equal(request.length, 24);
  assert.equal(request.readUInt16BE(2), 800); assert.equal(request.readUInt16BE(4), 600);
  assert.equal(request.readUInt32BE(8), 17); assert.equal(request.readUInt32BE(20), 0x10203040);
  assert.deepEqual(f.sizes.at(-1), [2, 2]);
  f.client.feed(extendedSize(800, 600, 1));
  assert.deepEqual(f.sizes.at(-1), [800, 600]);
  f.client.close();
});

test('resize coalesces viewports and does not loop on rejection', async () => {
  const f = fixture(); init(f.client); f.client.feed(extendedSize(2, 2));
  f.client.requestResize(640, 480, 0);
  f.client.requestResize(1024, 768, 0); await pause();
  assert.equal(f.sent.filter(b => b[0] === 251).length, 1);
  assert.equal(Buffer.from(f.sent.find(b => b[0] === 251)).readUInt16BE(2), 1024);
  f.client.feed(extendedSize(2, 2, 1, 3));
  assert.deepEqual(f.sizes.at(-1), [2, 2]);
  f.client.requestResize(1024, 768, 0); await pause();
  assert.equal(f.sent.filter(b => b[0] === 251).length, 1);
  f.client.requestResize(1280, 720, 0); await pause();
  assert.equal(f.sent.filter(b => b[0] === 251).length, 2);
  f.client.close();
});

test('pending resize sends latest viewport only after response, close cancels timer', async () => {
  const f = fixture(); init(f.client); f.client.feed(extendedSize(2, 2));
  f.client.requestResize(800, 600, 0); await pause();
  f.client.requestResize(900, 700, 0); await pause();
  assert.equal(f.sent.filter(b => b[0] === 251).length, 1);
  f.client.feed(extendedSize(800, 600, 1));
  f.client.scheduleResize(0); await pause();
  assert.equal(f.sent.filter(b => b[0] === 251).length, 2);
  f.client.feed(extendedSize(900, 700, 1));
  f.client.requestResize(1000, 800, 0); f.client.close(); await pause();
  assert.equal(f.sent.filter(b => b[0] === 251).length, 2);
});

test('automatic viewport limits preserve aspect ratio', () => {
  assert.deepEqual(viewportSize(3840, 2160), [1920, 1080]);
  assert.deepEqual(viewportSize(800, 1200), [720, 1080]);
  assert.deepEqual(viewportSize(800, 600), [800, 600]);
  assert.deepEqual(viewportSize(1, 1e9), [1, 1080]);
  assert.deepEqual(viewportSize(1e9, 1), [1920, 1]);
});
