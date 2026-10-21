import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import vm from 'node:vm';
const protocol = await readFile(new URL('./client.js', import.meta.url), 'utf8');
const {RFB, keySym} = await import('data:text/javascript;base64,' + Buffer.from(protocol).toString('base64'));
const source = (await readFile(new URL('./desktop.js', import.meta.url), 'utf8')).replace(/^import .*\n/, '');

for (const page of ['http://localhost:8080/', 'https://ood.example/rnode/compute/8080/', 'https://ood.example/node/compute/8080/']) {
 test(`canvas input and reconnect under ${page}`, () => {
  const listeners = {}, canvasListeners = {}, timers = new Map(), sockets = [], draws = [];
  let timer = 0, focused = false;
  const canvas = {width:300,height:150,style:{},
   getContext:()=>({putImageData:(...args)=>draws.push(args)}),
   focus(){focused=true;}, getBoundingClientRect:()=>({left:10,top:20,width:100,height:100}),
   addEventListener:(name,fn)=>{canvasListeners[name]=fn;},
   requestPointerLock(){document.pointerLockElement=canvas;},
  };
  const document = {querySelector:id=>{assert.equal(id,'#screen');return canvas;}, pointerLockElement:null,
   addEventListener:(name,fn)=>{listeners[name]=fn;}, exitPointerLock(){this.pointerLockElement=null;}};
  class Socket {
   static OPEN=1;
   constructor(url){this.url=String(url);this.readyState=1;this.sent=[];sockets.push(this);}
   send(b){this.sent.push([...b]);}
   close(){this.readyState=3;}
   feed(b){this.onmessage({data:Uint8Array.from(b).buffer});}
   ready(){
    this.feed(Buffer.from('RFB 003.008\n'));this.feed([1,1]);this.feed([0,0,0,0]);
    const init=Buffer.alloc(24);init.writeUInt16BE(2);init.writeUInt16BE(2,2);this.feed(init);
   }
  }
  const globals = {document,window:{innerWidth:800,innerHeight:600,addEventListener:(name,fn)=>{listeners[name]=fn;}},
   location:{href:page},URL,RFB,keySym,Uint8Array,Uint8ClampedArray,ImageData:class{},WebSocket:Socket,console,
   setTimeout:fn=>{timers.set(++timer,fn);return timer;},clearTimeout:id=>timers.delete(id)};
  vm.runInNewContext(source,globals);
  const first=sockets[0];
  assert.equal(first.url,page.replace(/^http/,'ws')+'rfb');
  assert(!first.url.includes('?'),'credentials must not enter websocket URLs');
  first.ready();assert(focused);assert.equal(canvas.style.width,'600px');assert.equal(canvas.style.height,'600px');
  canvas.onkeydown({code:'KeyA',preventDefault(){}});
  assert.deepEqual(first.sent.at(-1),[4,1,0,0,0,0,0,97]);
  listeners.blur();assert.deepEqual(first.sent.at(-2),[4,0,0,0,0,0,0,97]);
  // Absolute mode, then CSS-scaled click and wheel.
  const mode=Buffer.alloc(16);mode.writeUInt16BE(1,2);mode.writeUInt16BE(1,4);mode.writeInt32BE(-257,12);first.feed(mode);
  canvas.onmousedown({clientX:109,clientY:119,button:0,preventDefault(){}});
  assert.deepEqual(first.sent.at(-1),[5,1,0,1,0,1]);
  listeners.mouseup({clientX:109,clientY:119,button:0});assert.deepEqual(first.sent.at(-1),[5,0,0,1,0,1]);
  canvasListeners.wheel({clientX:109,clientY:119,deltaY:1,preventDefault(){}});
  assert.deepEqual(first.sent.at(-2),[5,16,0,1,0,1]);
  // A real raw update reaches the canvas, not surrounding DOM.
  const frame=Buffer.alloc(32);frame.writeUInt16BE(1,2);frame.writeUInt16BE(2,8);frame.writeUInt16BE(2,10);first.feed(frame);
  assert.equal(draws.length,1);
  first.onclose();assert.equal(timers.size,1);
  const reconnect=[...timers.values()][0];timers.clear();reconnect();
  const second=sockets[1];second.ready();first.onclose();first.feed([99]);assert.equal(timers.size,0);
  // Relative input uses pointer lock and modulo coordinates when USB is off.
  canvas.onmousedown({button:0,preventDefault(){}});assert.equal(document.pointerLockElement,canvas);
  canvas.onmousemove({movementX:4,movementY:-3});assert.deepEqual(second.sent.at(-1),[5,0,128,4,127,253]);
  listeners.pagehide();assert.equal(second.readyState,3);second.onclose();assert.equal(timers.size,0);
 });
}
