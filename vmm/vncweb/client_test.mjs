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
