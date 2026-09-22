import {test} from 'node:test';
import assert from 'node:assert/strict';
import {RFB,keySym} from './client.js';

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
