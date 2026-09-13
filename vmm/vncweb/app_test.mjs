import {test} from 'node:test';
import assert from 'node:assert/strict';

test('tabs release input, ignore stale sockets, and select successfully created VMs', async () => {
  const nodes = new Map();
  const element = () => ({disabled:false, textContent:'', children:[], attributes:{},
    setAttribute(k,v){this.attributes[k]=v;}, replaceChildren(...children){this.children=children;},
    getContext(){return {clearRect(){},putImageData(){}};}, focus(){}, requestPointerLock(){}});
  for (const id of ['screen','status','connect','cad','tabs','create','vm-name']) nodes.set(`#${id}`,element());
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
    window:{addEventListener(){}},location:{hash:'#session',pathname:'/',protocol:'http:',host:'localhost'},
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
    await import('./app.js');
    await new Promise(resolve=>setImmediate(resolve));
    const first=sockets[0];first.ready();
    nodes.get('#screen').onkeydown({code:'KeyA',preventDefault(){}});
    nodes.get('#tabs').children[1].onclick();
    assert(first.sent.some(p=>JSON.stringify(p)==='[4,0,0,0,0,0,0,97]'),'held key released on old VM');
    assert.equal(first.readyState,3);
    const second=sockets[1];second.ready();
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
