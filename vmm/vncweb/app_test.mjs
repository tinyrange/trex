import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import vm from 'node:vm';
const clientSource = await readFile(new URL('./client.js', import.meta.url), 'utf8');
const {RFB, keySym} = await import('data:text/javascript;base64,' + Buffer.from(clientSource).toString('base64'));
const appSource = (await readFile(new URL('./app.js', import.meta.url), 'utf8')).replace(/^import .*\n/, '');
test('viewer switches consoles, releases held input and ignores stale socket events', async () => {
  const elements = new Map();
  const element = () => ({style: {}, children: [], addEventListener() {}, setAttribute() {}, replaceChildren(...items) {this.children = items;}, getContext() {return {clearRect() {}, putImageData() {}};}, focus() {}, getBoundingClientRect() {return {left: 10, top: 20, width: 100, height: 100};}});
  for (const id of ['screen', 'status', 'connect', 'cad', 'tabs', 'create', 'vm-name']) elements.set('#' + id, element());
  elements.get('#screen').parentElement = {...element(), clientWidth: 800};
  const listeners = {}, sockets = [], storage = new Map();
  class Socket {
    static OPEN = 1; static CLOSING = 2;
    constructor(url) {this.url = url; this.readyState = 1; this.sent = []; sockets.push(this);}
    send(b) {this.sent.push([...b]);}
    close() {this.readyState = 3;}
    feed(b) {this.onmessage({data: Uint8Array.from(b).buffer});}
  }
  const context = {RFB, keySym, Uint8Array, Uint8ClampedArray, ImageData: class {}, WebSocket: Socket,
    document: {querySelector: id => elements.get(id), createElement: element, addEventListener() {}},
    window: {innerHeight: 600, addEventListener: (name, fn) => {listeners[name] = fn;}},
    ResizeObserver: class {observe() {}}, getComputedStyle: () => ({paddingLeft:'0',paddingRight:'0',paddingTop:'0',paddingBottom:'0'}),
    location: {hash: '#test-token', pathname: '/', protocol: 'http:', host: 'localhost'},
    sessionStorage: {getItem: k => storage.get(k), setItem: (k, v) => storage.set(k, v)}, history: {replaceState() {}},
    setTimeout, clearTimeout,
    fetch: async () => ({ok: true, json: async () => ({vms: [{id: '1', name: 'First'}, {id: '2', name: 'Second'}], canCreate: false})})};
  vm.runInNewContext(appSource, context);
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(sockets.length, 1); assert.match(sockets[0].url, /vm=1/);
  function handshake(ws) {
    ws.feed(Buffer.from('RFB 003.008\n')); ws.feed([1, 1]); ws.feed([0, 0, 0, 0]);
    const init = Buffer.alloc(24); init.writeUInt16BE(2); init.writeUInt16BE(2, 2); ws.feed(init);
  }
  handshake(sockets[0]);
  assert.equal(elements.get('#status').textContent, 'Connected');
  const layout = Buffer.alloc(36); layout.writeUInt16BE(1, 2); layout.writeUInt16BE(2, 8); layout.writeUInt16BE(2, 10);
  layout.writeInt32BE(-308, 12); layout[16] = 1; layout.writeUInt16BE(2, 28); layout.writeUInt16BE(2, 30);
  sockets[0].feed(layout);
  await new Promise(resolve => setTimeout(resolve, 220));
  const resize = Buffer.from(sockets[0].sent.find(b => b[0] === 251));
  assert.equal(resize.readUInt16BE(2), 800); assert.equal(resize.readUInt16BE(4), 580);
  elements.get('#screen').onkeydown({code: 'ControlLeft', preventDefault() {}});
  listeners.blur(); assert.deepEqual(sockets[0].sent.at(-2), [4, 0, 0, 0, 0, 0, 255, 227]);
  elements.get('#tabs').children[1].onclick();
  assert.equal(sockets[0].readyState, 3); assert.equal(sockets.length, 2);
  sockets[0].onclose(); sockets[0].feed([99]);
  assert.equal(elements.get('#status').textContent, 'Connecting…');
  handshake(sockets[1]);
  const mode = Buffer.alloc(16); mode.writeUInt16BE(1, 2); mode.writeUInt16BE(1, 4); mode.writeInt32BE(-257, 12); sockets[1].feed(mode);
  elements.get('#screen').onmousemove({clientX: 999, clientY: -99});
  assert.deepEqual(sockets[1].sent.at(-1), [5, 0, 0, 1, 0, 0]);
  elements.get('#connect').onclick(); assert.equal(sockets[1].readyState, 3);
  assert.equal(elements.get('#cad').disabled, true);
});

test('tabs release input, ignore stale sockets, and select successfully created VMs', async () => {
  const nodes = new Map();
  const element = () => ({disabled:false, textContent:'', children:[], attributes:{}, style:{},
    addEventListener(){}, getBoundingClientRect(){return {left:10,top:20,width:100,height:100};},
    setAttribute(k,v){this.attributes[k]=v;}, replaceChildren(...children){this.children=children;},
    getContext(){return {clearRect(){},putImageData(){}};}, focus(){}, requestPointerLock(){}});
  for (const id of ['screen','status','connect','cad','tabs','create','vm-name']) nodes.set(`#${id}`,element());
  nodes.get('#screen').parentElement = {...element(), clientWidth: 800};
  const sockets=[];
  class Socket {
    static OPEN=1; static CLOSING=2;
    constructor(url){this.url=url;this.readyState=1;this.sent=[];sockets.push(this);}
    send(bytes){this.sent.push([...bytes]);}
    close(){this.readyState=3;}
    feed(bytes){this.onmessage({data:Uint8Array.from(bytes).buffer});}
    ready(){
      this.feed(new TextEncoder().encode('RFB 003.008\n'));this.feed([1,1]);this.feed([0,0,0,0]);
      const init=new Uint8Array(24);init[1]=2;init[3]=2;this.feed(init);
    }
  }
  let catalog=[{id:'1',name:'DOMAIN31'},{id:'2',name:'CLIENT31'}], finish, fail=false;
  const previous=new Map();
  const globals={
    document:{querySelector:id=>nodes.get(id),createElement:element,addEventListener(){},pointerLockElement:null},
    window:{innerHeight:600,addEventListener(){}},location:{hash:'#session',pathname:'/',protocol:'http:',host:'localhost'},
    ResizeObserver:class{observe(){}},getComputedStyle:()=>({paddingLeft:'0',paddingRight:'0',paddingTop:'0',paddingBottom:'0'}),
    history:{replaceState(){}},sessionStorage:{getItem(){return null;},setItem(){}},WebSocket:Socket,
    fetch:async (url,options)=>{
      assert.equal(url,'/api/vms');assert.equal(options.headers.Authorization,'Bearer session');
      if(options.method==='POST') {
        if(fail)return {ok:false,text:async()=> 'domain account creation failed'};
        await new Promise(resolve=>{finish=resolve;});
        catalog.push({id:'3',name:'CLIENT32'});
        return {ok:true,json:async()=>catalog[2]};
      }
      return {ok:true,json:async()=>({vms:catalog,canCreate:true,creating:false})};
    },
  };
  for(const [key,value] of Object.entries(globals)){previous.set(key,globalThis[key]);globalThis[key]=value;}
  try {
    vm.runInNewContext(appSource, {...globals, RFB, keySym, Uint8Array, Uint8ClampedArray, setTimeout, clearTimeout});
    await new Promise(resolve=>setImmediate(resolve));
    const first=sockets[0];first.ready();
    nodes.get('#screen').onkeydown({code:'KeyA',preventDefault(){}});
    nodes.get('#tabs').children[1].onclick();
    assert(first.sent.some(p=>JSON.stringify(p)==='[4,0,0,0,0,0,0,97]'),'held key released on old VM');
    assert.equal(first.readyState,3);
    const second=sockets[1];second.ready();
    second.feed([0,0,0,1,0,1,0,0,0,2,0,2,255,255,254,255]);
    nodes.get('#screen').onmousedown({clientX:109,clientY:119,button:0,preventDefault(){}});
    assert.deepEqual(second.sent.at(-1),[5,1,0,1,0,1],'absolute click maps CSS coordinates to framebuffer pixels');
    first.onclose();
    assert.equal(nodes.get('#cad').disabled,false,'old socket must not disable new VM');
    assert.equal(nodes.get('#vm-name').textContent,'CLIENT31');
    const creation=nodes.get('#create').onclick();
    assert.equal(nodes.get('#create').disabled,true);
    finish();await creation;
    assert.equal(nodes.get('#tabs').children.length,3);
    assert.equal(nodes.get('#vm-name').textContent,'CLIENT32');
    assert(sockets[2].url.endsWith('&vm=3'));
    assert.equal(nodes.get('#create').disabled,false);
    fail=true;await nodes.get('#create').onclick();
    assert.match(nodes.get('#status').textContent,/domain account creation failed/);
    assert.equal(sockets.length,3,'failed creation must keep the current VM');
    nodes.get('#connect').onclick();
  } finally {
    for(const [key,value] of previous){if(value===undefined)delete globalThis[key];else globalThis[key]=value;}
  }
});
