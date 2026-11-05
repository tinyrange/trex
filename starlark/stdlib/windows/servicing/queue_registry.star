"""Read-only IRtl SIL bridge for native queue transformer-state queries.

The pinned WCP code owns all interpretation and queue decisions. This bridge
supplies bytes from explicit source/target hives, including genuine not-found
results. It cannot create keys, write values, or consult the host registry.
"""

def create_queue_registry(m, hives, state, label, allocate, deallocate):
    """Read only the native queue transformer's established registry paths."""
    return _create_registry(m,hives,state,label,allocate,deallocate,"queue")

def create_executor_registry(m, hives, state, label, allocate, deallocate):
    """Read only the native executor's HKCU eligibility policy path."""
    return _create_registry(m,hives,state,label,allocate,deallocate,"executor")

def create_configuration_registry(m, software, state, label, allocate, deallocate):
    """Return (SIL, optional SideBySide/Configuration key) for native options."""
    return _create_registry(m,{"SOFTWARE":software},state,label,allocate,deallocate,"configuration")

def create_install_map_registry(m, hives, state, label, allocate, deallocate):
    """Read only SOFTWARE's native Winners map; return (SIL, map root key)."""
    return _create_registry(m,hives,state,label,allocate,deallocate,"install-map")

def _create_registry(m, hives, state, label, allocate, deallocate, profile):
    """Create one SIL. state must belong to the caller's emulator.plugin.

    allocate is the pinned native WCP allocator address; buffers returned in
    LBLOBs belong to that allocator and are released by real RtlFreeLBlob.
    """
    if sorted(hives)!=(["COMPONENTS","SYSTEM"] if profile=="queue" else ["SOFTWARE"]):
        fail("native registry bridge requires explicit "+profile+" snapshots")
    objects={}
    state[label]=dict(objects=objects,queries=[],next_object=0)
    local=state[label]
    def text(m,p):
        n=m.read_u64le(p)
        if n>m.read_u64le(p+8) or n>65534 or n%2:
            fail("invalid queue registry LUNICODE_STRING")
        result=binary.text(m.read(m.read_pointer(p+16),n),encoding="utf16le")
        if chr(0) in result: fail("embedded NUL in queue registry name")
        return result
    def lookup(hive,parts):
        folded=tuple([v.lower() for v in parts])
        allowed=(hive=="COMPONENTS" and (folded==("deriveddata",) or folded[:2]==("deriveddata","transformsettingsversion"))) or (hive=="SYSTEM" and folded==("setup","buildupdate"))
        if profile=="install-map":
            allowed=hive=="SOFTWARE" and folded[:5]==("microsoft","windows","currentversion","sidebyside","winners")
        if profile=="configuration":
            allowed=hive=="SOFTWARE" and folded in [
                ("microsoft","windows","currentversion","policies","servicing"),
                ("microsoft","windows","currentversion","sidebyside","configuration"),
            ]
        if profile=="executor":
            allowed=hive=="SOFTWARE" and folded==("microsoft","windows","currentversion","component based servicing","packagespending")
        if not allowed: fail("native queue registry query outside established authority: "+hive+str(parts))
        if len(parts)>128 or any([not p or p in [".",".."] for p in parts]): fail("invalid queue registry key")
        return hives[hive].find(parts)
    def record(kind,hive,parts,name=None):
        if len(local["queries"])>=4096: fail("queue registry query bound exceeded")
        local["queries"].append(dict(kind=kind,hive=hive,parts=parts,name=name))
    def unsupported(e):
        fail("unsupported read-only queue registry operation: "+e.name)
    def release(e):
        obj=objects.get(e.args[0])
        if obj==None or obj["refs"]<1: fail("queue registry release after final reference")
        obj["refs"]-=1
        return 0
    def object(kind,methods,data=None):
        index=local["next_object"]
        if index>=4096: fail("queue registry object bound exceeded")
        local["next_object"]+=1
        table=m.allocate(size=32*8,name=label+" "+kind+" vtable")
        pointer=m.allocate(size=8,name=label+" "+kind)
        m.write_pointer(pointer,table)
        objects[pointer]=dict(refs=1,data=data,table=table)
        for slot in range(32):
            fn,argc=methods.get(slot,(unsupported,1))
            m.write_pointer(table+slot*8,m.provide_export(fn,module="trex.csi",name="queue_%s_%s_%d_%d"%(label,kind,index,slot),argc=argc))
        return pointer
    def query_interface(e):
        obj=objects.get(e.args[0])
        if profile!="install-map" or obj==None or obj["refs"]<1:
            fail("invalid native install-map QueryInterface")
        identifier="a6fd78f7c4f0e649945183982762d015" if obj["data"]!=None else "b1479dc11f214b4c8af80ddff741fee7"
        if hex(e.machine.read(e.args[1],16))!=identifier:
            fail("unimplemented native registry interface")
        obj["refs"]+=1
        e.machine.write_pointer(e.args[2],e.args[0])
        return 0
    def key_object(hive,parts):
        return object("IRtlKey",{0:(release,1),1:(query_interface,3),13:(open_relative,6),19:(query,6)},(hive,parts))
    def key_data(pointer):
        obj=objects.get(pointer)
        if obj==None or obj["refs"]<1 or obj["data"]==None: fail("invalid queue registry key object")
        return obj["data"]
    def opened(e,hive,parts,out,disposition):
        node=lookup(hive,parts)
        record("open",hive,parts)
        e.machine.write_pointer(out,key_object(hive,parts) if node!=None else 0)
        e.machine.write_u32le(disposition,1 if node!=None else 2)
        return 0
    def open_absolute(e):
        a=e.args
        if a[1]!=1 or a[2]!=0x20019 or not a[4] or not a[5]: fail("unsupported queue registry absolute-open flags")
        parts=text(e.machine,a[3]).split(chr(92))
        if len(parts)<5 or [v.lower() for v in parts[:3]]!=["","registry","machine"]: fail("invalid queue registry absolute path")
        return opened(e,parts[3].upper(),parts[4:],a[4],a[5])
    def open_relative(e):
        a=e.args
        if a[1]!=1 or a[2]!=0x20019 or e.machine.read_u64le(a[3])!=40 or e.machine.read_u32le(a[3]+16) not in ([0,0x40] if profile=="install-map" else [0x40]) or e.machine.read_u64le(a[3]+24)!=0 or e.machine.read_u64le(a[3]+32)!=0:
            fail("unsupported queue registry relative-open attributes")
        hive,parts=key_data(a[0])
        child=text(e.machine,e.machine.read_pointer(a[3]+8)).split(chr(92))
        return opened(e,hive,parts+child,a[4],a[5])
    def query(e):
        a=e.args
        if a[1]!=1 or a[3]!=2: fail("unsupported queue registry value query")
        hive,parts=key_data(a[0])
        name=text(e.machine,a[2])
        node=lookup(hive,parts)
        record("value",hive,parts,name)
        found=[v for n,v in node.value_records.items() if ("" if n=="(default)" else n).lower()==name.lower()]
        if len(found)>1: fail("ambiguous queue registry value")
        if not found:
            e.machine.write_u32le(a[5],1)
            return 0
        value=found[0]
        if len(value.raw)>1048576: fail("queue registry value exceeds bound")
        data=binary.concat([binary.u32le(0),binary.u32le(value.type),binary.u32le(len(value.raw)),value.raw]).bytes()
        capacity=e.machine.read_u64le(a[4]+8)
        p=e.machine.read_pointer(a[4]+16)
        if capacity<len(data):
            result=e.machine.invoke(allocate,args=[len(data)])
            if result.reason!="return" or not result.value: fail("queue registry native buffer allocation failed")
            if p:
                freed=e.machine.invoke(deallocate,args=[p])
                if freed.reason!="return": fail("queue registry native buffer release failed")
            p=result.value
            capacity=len(data)
        if not p: fail("queue registry has a null value buffer")
        e.machine.write(p,data)
        e.machine.write_u64le(a[4],len(data))
        e.machine.write_u64le(a[4]+8,capacity)
        e.machine.write_pointer(a[4]+16,p)
        e.machine.write_u32le(a[5],2)
        return 0
    sil=object("SIL",{0:(release,1),1:(query_interface,3),5:(open_absolute,6)})
    if profile=="configuration":
        parts=["Microsoft","Windows","CurrentVersion","SideBySide","Configuration"]
        return (sil,key_object("SOFTWARE",parts) if lookup("SOFTWARE",parts)!=None else 0)
    if profile=="install-map":
        parts=["Microsoft","Windows","CurrentVersion","SideBySide","Winners"]
        if lookup("SOFTWARE",parts)==None:
            fail("native install-map root is absent")
        return (sil,key_object("SOFTWARE",parts))
    return sil
