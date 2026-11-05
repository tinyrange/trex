"""Bounded CSI registry-key flags bridge, backed by explicit offline hives.

The native installer chooses keys, recursion and flags. This bridge records
uncommitted metadata edits; it neither creates keys nor publishes a hive.

Pinned target-kernel evidence: CmQueryKey 0x85878a returns class-5's three
DWORDs (UserFlags, key flags, virtualization flags). CmSetKeyFlags 0x9af0fb
sets nk+0x34 bits20..23; disable bit2 also clears nk.Flags bit0x80. The native
luainstall ApplyRegistryKeyRecurse reads the third DWORD, ORs its selected
policy, and calls IRtlKey slot27/class2. Enumeration names remain borrowed
until the next batch or enumerator release; LBLOBs use WCP's own allocator.
"""

def create_key_flags_registry(m, hives, state, allocate, deallocate):
    """Allocate native key-flags registry interfaces using explicit SOFTWARE/SYSTEM hives and caller-owned allocation callbacks."""
    if sorted(hives)!=["SOFTWARE","SYSTEM"]: fail("key flags require explicit target hives")
    state["key_flags_registry"]=dict(objects={},next_object=0,flags={},patches=[],queries=0)
    local=state["key_flags_registry"]
    objects=local["objects"]
    select=hives["SYSTEM"].find("/Select")
    current=None if select==None else select.values.get("Current")
    if type(current)!="int" or current<1 or current>999 or select.value_records["Current"].type!=4: fail("invalid target control set")
    control="ControlSet"+("00"+str(current))[-3:]
    def text(p):
        n=m.read_u64le(p)
        if n>m.read_u64le(p+8) or n>65534 or n%2: fail("invalid key flags LUNICODE_STRING")
        value=binary.text(m.read(m.read_pointer(p+16),n),encoding="utf16le")
        if chr(0) in value: fail("NUL in key flags path")
        return value
    def lookup(hive,parts):
        if hive not in hives or not parts or len(parts)>128 or any([not p or p in [".",".."] for p in parts]): fail("invalid key flags path")
        node=hives[hive].find(parts)
        if node==None: fail("native key flags requires existing key: "+hive+str(parts))
        # This adapter does not follow registry links or model volatile keys.
        if node.flags&0x11: fail("volatile or symbolic key not admitted")
        return node
    def data(pointer):
        obj=objects.get(pointer)
        if obj==None or obj["refs"]!=1: fail("released key flags object")
        return obj["data"]
    def release(e):
        data(e.args[0])
        obj=objects[e.args[0]]
        for p in obj["owned"]: m.free(p)
        obj["refs"]=0
        return 0
    def unsupported(e): fail("unsupported key flags interface: "+e.name)
    def object(kind,methods,value=None):
        index=local["next_object"]
        if index>=16384: fail("key flags object bound")
        local["next_object"]+=1
        table=m.allocate(size=32*8,name="key flags "+kind+" vtable")
        pointer=m.allocate(size=8,name="key flags "+kind)
        m.write_pointer(pointer,table)
        objects[pointer]=dict(refs=1,data=value,owned=[])
        for slot in range(32):
            fn,argc=methods.get(slot,(unsupported,1))
            m.write_pointer(table+slot*8,m.provide_export(fn,module="trex.csi",name="keyflags_%s_%d_%d"%(kind,index,slot),argc=argc))
        return pointer
    def key(hive,parts):
        lookup(hive,parts)
        return object("IRtlKey",{0:(release,1),10:(query,3),13:(open_relative,6),25:(enumerate_keys,3),27:(set_flags,4)},(hive,parts))
    def open_absolute(e):
        a=e.args
        if a[1]!=2 or a[2]!=0x2001f or not a[4] or a[5]: fail("unsupported key flags absolute open")
        parts=text(a[3]).rstrip(chr(92)).split(chr(92))
        if len(parts)<5 or [p.lower() for p in parts[:3]]!=["","registry","machine"]: fail("invalid key flags absolute path")
        hive,parts=parts[3].upper(),parts[4:]
        if hive=="SYSTEM" and parts[0].lower()=="currentcontrolset": parts[0]=control
        m.write_pointer(a[4],key(hive,parts))
        return 0
    def open_relative(e):
        a=e.args
        if a[1]!=2 or a[2]!=0x2001f or m.read_u64le(a[3])!=40 or m.read_u32le(a[3]+16)!=0x40 or m.read_u64le(a[3]+24) or m.read_u64le(a[3]+32) or a[5]: fail("unsupported key flags relative open")
        hive,parts=data(a[0])
        m.write_pointer(a[4],key(hive,parts+text(m.read_pointer(a[3]+8)).split(chr(92))))
        return 0
    def query(e):
        a=e.args
        if a[1]!=5: fail("unsupported key flags information class")
        local["queries"]+=1
        if local["queries"]>65536: fail("key flags query bound")
        hive,parts=data(a[0])
        node=lookup(hive,parts)
        identity=(hive,tuple([p.lower() for p in parts]))
        flags=local["flags"].get(identity,node.virtualization_flags)
        # Pinned CmQueryKey class 5: UserFlags, stable-key flags, VirtFlags.
        raw=binary.concat([binary.u32le(node.user_flags),binary.u32le(0),binary.u32le(flags)]).bytes()
        capacity=m.read_u64le(a[2]+8)
        pointer=m.read_pointer(a[2]+16)
        if capacity<len(raw):
            result=m.invoke(allocate,args=[len(raw)])
            if result.reason!="return" or not result.value: fail("key flags native allocation failed")
            if pointer:
                freed=m.invoke(deallocate,args=[pointer])
                if freed.reason!="return": fail("key flags native buffer release failed")
            pointer=result.value
            capacity=len(raw)
        if not pointer: fail("null key flags buffer")
        m.write(pointer,raw)
        m.write_u64le(a[2],len(raw))
        m.write_u64le(a[2]+8,capacity)
        m.write_pointer(a[2]+16,pointer)
        return 0
    def set_flags(e):
        a=e.args
        if a[1]!=2 or a[3]!=4: fail("unsupported key flags set class")
        flags=m.read_u32le(a[2])
        if flags>15: fail("invalid virtualization flags")
        hive,parts=data(a[0])
        lookup(hive,parts)
        if len(local["patches"])>=65536: fail("key flags patch bound")
        local["flags"][(hive,tuple([p.lower() for p in parts]))]=flags
        local["patches"].append(dict(hive=hive,key_parts=parts,virtualization_flags=flags))
        return 0
    def enumerate_keys(e):
        if e.args[1]!=0: fail("unsupported key flags enumeration")
        hive,parts=data(e.args[0])
        names=[child.name for child in lookup(hive,parts).children]
        if len(names)>65536: fail("key flags children bound")
        pointer=object("IRtlKeyNameEnumerator",{0:(release,1),2:(next_names,3)},dict(names=names,index=0))
        m.write_pointer(e.args[2],pointer)
        return 0
    def next_names(e):
        a=e.args
        obj=data(a[0])
        array=m.read_pointer(a[1])
        capacity=m.read_u64le(a[1]+8)
        if capacity>4096: fail("key flags enumeration capacity")
        for p in objects[a[0]]["owned"]: m.free(p)
        objects[a[0]]["owned"]=[]
        batch=obj["names"][obj["index"]:obj["index"]+capacity]
        for i,name in enumerate(batch):
            raw=binary.encode(name,encoding="utf16le")
            string=m.allocate(value=raw,name="key flags child name")
            descriptor=m.allocate(size=24,name="key flags child descriptor")
            objects[a[0]]["owned"].extend([string,descriptor])
            m.write_u64le(descriptor,len(raw))
            m.write_u64le(descriptor+8,len(raw))
            m.write_pointer(descriptor+16,string)
            m.write_pointer(array+i*8,descriptor)
        obj["index"]+=len(batch)
        m.write_u64le(a[2],len(batch))
        return 0
    return object("SIL",{0:(release,1),5:(open_absolute,6)})
