// RFB 3.8 client. No third-party libraries; all integers on the wire are big
// endian except the negotiated RGB pixel words. Parsing survives any WS split.
export class RFB {
  constructor(send, frame, resize, ready) {
    Object.assign(this, {send, frame, resize, ready});
    this.buffer = new Uint8Array(); this.state = 'version'; this.rectangles = 0;
  }
  feed(data) {
    if (this.buffer.length + data.length > 70 * 1024 * 1024) throw Error('RFB receive limit exceeded');
    const joined = new Uint8Array(this.buffer.length + data.length);
    joined.set(this.buffer); joined.set(data, this.buffer.length); this.buffer = joined;
    while (this.parse()) {}
  }
  take(n) { const b = this.buffer.slice(0,n); this.buffer = this.buffer.subarray(n); return b; }
  parse() {
    const b = this.buffer, v = new DataView(b.buffer,b.byteOffset,b.byteLength);
    if (this.state === 'version') {
      if (b.length < 12) return false;
      if (new TextDecoder().decode(this.take(12)) !== 'RFB 003.008\n') throw Error('RFB 3.8 required');
      this.send(new TextEncoder().encode('RFB 003.008\n')); this.state = 'security';
    } else if (this.state === 'security') {
      if (!b.length) return false;
      if (!b[0]) throw Error('Server rejected connection');
      if (b.length < 1+b[0]) return false;
      if (!this.take(1+b[0]).subarray(1).includes(1)) throw Error('Unsupported RFB authentication');
      this.send(Uint8Array.of(1)); this.state = 'result';
    } else if (this.state === 'result') {
      if (b.length < 4) return false;
      if (v.getUint32(0)) throw Error('RFB authentication failed');
      this.take(4); this.send(Uint8Array.of(1)); this.state = 'init';
    } else if (this.state === 'init') {
      if (b.length < 24) return false;
      const n = v.getUint32(20); if (n > 65536) throw Error('Server name too long');
      if (b.length < 24+n) return false;
      this.size(v.getUint16(0),v.getUint16(2)); this.take(24+n);
      this.send(Uint8Array.of(0,0,0,0,32,24,0,1,0,255,0,255,0,255,0,8,16,0,0,0));
      this.send(Uint8Array.of(2,0,0,2,0,0,0,0,255,255,255,33));
      this.state = 'message'; this.ready(); this.request(false);
    } else if (this.state === 'message') {
      if (!b.length) return false;
      if (b[0] === 2) { this.take(1); return true; }
      if (b[0] !== 0) throw Error('Unsupported server message');
      if (b.length < 4) return false;
      this.rectangles = v.getUint16(2); this.take(4); this.state = this.rectangles ? 'rectangle' : 'message';
      if (!this.rectangles) this.next();
    } else if (this.state === 'rectangle') {
      if (b.length < 12) return false;
      const x=v.getUint16(0), y=v.getUint16(2), w=v.getUint16(4), h=v.getUint16(6), enc=v.getInt32(8);
      if (enc === -223) { this.take(12); this.size(w,h); }
      else {
        if (enc !== 0 || !w || !h || x+w>this.width || y+h>this.height) throw Error('Invalid RFB rectangle');
        const n=w*h*4; if (b.length < 12+n) return false;
        this.take(12); const pixels=this.take(n); for(let i=3;i<n;i+=4) pixels[i]=255;
        this.frame(x,y,w,h,pixels);
      }
      if (--this.rectangles === 0) { this.state='message'; this.next(); }
    }
    return true;
  }
  size(w,h) { if (!w||!h||w>4096||h>4096) throw Error('Invalid display dimensions'); this.width=w;this.height=h;this.resize(w,h); }
  next() { clearTimeout(this.timer); this.timer=setTimeout(()=>this.request(true),50); }
  close() { clearTimeout(this.timer); }
  request(incremental) { const b=new Uint8Array(10),v=new DataView(b.buffer);b[0]=3;b[1]=+incremental;v.setUint16(6,this.width);v.setUint16(8,this.height);this.send(b); }
  key(key,down) { const b=new Uint8Array(8); b[0]=4;b[1]=+down;new DataView(b.buffer).setUint32(4,key);this.send(b); }
  pointer(x,y,buttons) {const b=new Uint8Array(6),v=new DataView(b.buffer);b[0]=5;b[1]=buttons;v.setUint16(2,x);v.setUint16(4,y);this.send(b);}
}

export function keySym(code) {
  if (/^Key[A-Z]$/.test(code)) return code.charCodeAt(3)+32;
  if (/^Digit[0-9]$/.test(code)) return code.charCodeAt(5);
  if (/^F([1-9]|1[0-2])$/.test(code)) return 0xffbd+Number(code.slice(1));
  return ({Escape:0xff1b,Backspace:0xff08,Tab:0xff09,Enter:0xff0d,Space:32,ShiftLeft:0xffe1,ShiftRight:0xffe2,ControlLeft:0xffe3,ControlRight:0xffe4,AltLeft:0xffe9,AltRight:0xffea,CapsLock:0xffe5,Delete:0xffff,Insert:0xff63,Home:0xff50,End:0xff57,PageUp:0xff55,PageDown:0xff56,ArrowLeft:0xff51,ArrowUp:0xff52,ArrowRight:0xff53,ArrowDown:0xff54,Minus:45,Equal:61,BracketLeft:91,BracketRight:93,Semicolon:59,Quote:39,Backquote:96,Backslash:92,Comma:44,Period:46,Slash:47})[code];
}

if (typeof document !== 'undefined') {
  const canvas=document.querySelector('#screen'),context=canvas.getContext('2d'),status=document.querySelector('#status'),button=document.querySelector('#connect'),cad=document.querySelector('#cad');
  const token=location.hash.slice(1)||sessionStorage.getItem('trex-vnc-token');
  if(token)sessionStorage.setItem('trex-vnc-token',token);
  history.replaceState(null,'',location.pathname);
  let socket,rfb,active=false,buttons=0,x=32768,y=32768;const held=new Set();
  const release=()=>{if(active){for(const key of held)rfb.key(key,false);rfb.pointer(x,y,0);}held.clear();buttons=0;};
  const stop=()=>{release();active=false;cad.disabled=true;rfb?.close();socket?.close();button.textContent='Connect';if(document.pointerLockElement===canvas)document.exitPointerLock();};
  button.onclick=()=>{
    if(socket && socket.readyState<2){stop();return;}
    if(!token){status.textContent='Open the complete session URL printed by trex.';return;}
    status.textContent='Connecting…';button.textContent='Disconnect';
    const ws=new WebSocket(`${location.protocol==='https:'?'wss':'ws'}://${location.host}/rfb?token=${encodeURIComponent(token)}`);socket=ws;ws.binaryType='arraybuffer';
    const client=new RFB(b=>{if(ws.readyState===1)ws.send(b);},(x,y,w,h,p)=>context.putImageData(new ImageData(new Uint8ClampedArray(p.buffer,p.byteOffset,p.length),w,h),x,y),(w,h)=>{canvas.width=w;canvas.height=h;},()=>{active=true;cad.disabled=false;status.textContent='Connected';client.pointer(x,y,0);});rfb=client;
    ws.onmessage=e=>{if(socket!==ws)return;try{client.feed(new Uint8Array(e.data));}catch(err){status.textContent=err.message;stop();}};
    ws.onerror=()=>{if(socket===ws)status.textContent='Connection failed. Check the session URL and whether another browser is connected.';};
    ws.onclose=()=>{client.close();if(socket===ws){held.clear();active=false;cad.disabled=true;button.textContent='Connect';if(status.textContent==='Connected')status.textContent='Disconnected';}};
  };
  canvas.onmousedown=e=>{if(!active)return;e.preventDefault();canvas.focus();if(document.pointerLockElement!==canvas){canvas.requestPointerLock();return;}buttons|=({0:1,1:2,2:4})[e.button]||0;rfb.pointer(x,y,buttons);};
  window.addEventListener('mouseup',e=>{if(!active)return;buttons&=~(({0:1,1:2,2:4})[e.button]||0);rfb.pointer(x,y,buttons);});
  canvas.onmousemove=e=>{if(!active||document.pointerLockElement!==canvas)return;x=(x+e.movementX)&65535;y=(y+e.movementY)&65535;rfb.pointer(x,y,buttons);};
  canvas.oncontextmenu=e=>e.preventDefault();
  canvas.onkeydown=e=>{if(!active)return;const key=keySym(e.code);if(key){e.preventDefault();held.add(key);rfb.key(key,true);}};
  canvas.onkeyup=e=>{if(!active)return;const key=keySym(e.code);if(key){e.preventDefault();held.delete(key);rfb.key(key,false);}};
  canvas.onblur=release;window.addEventListener('blur',release);document.addEventListener('pointerlockchange',()=>{if(document.pointerLockElement!==canvas)release();});
  cad.onclick=()=>{if(!active)return;release();const keys=[0xffe3,0xffe9,0xffff];keys.forEach(k=>{held.add(k);rfb.key(k,true);});setTimeout(release,100);};
  if(token)button.click();
}
