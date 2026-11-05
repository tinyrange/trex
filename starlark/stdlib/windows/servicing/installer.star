"""Bounded native CSI basic-installer execution against an offline registry.

This is an explicit, narrow CSI ABI adapter, not an implementation of an
installer's decisions. Unsupported methods stop execution without publication.
"""
load("@stdlib//windows/emulation:runner.star", native_run="run")

_BASIC_IID = binary.decode("ca9f29c77320a642b2a48c1fc18ac3dd", "hex")

def expand_csi_windows_path(text):
    """Expand the explicit target Windows-root token, rejecting other namespaces."""
    token="$(runtime.windows)"
    slash=chr(92)
    if text!=token and not text.startswith(token+slash): fail("unsupported CSI path expansion")
    suffix=text[len(token):]
    if "$" in suffix or len(text)>32767 or suffix and any([not part or part in [".",".."] for part in suffix[1:].split(slash)]):
        fail("unresolved or non-canonical CSI path expansion")
    return "C:"+slash+"Windows"+suffix

def run_http_installer(file, system, rows, instruction_limit=500000, operation="install", phase=10):
    """Run the bounded native HTTP profile with explicit SYSTEM bytes, rows, operation and phase; return captured effects."""
    return run_basic_installer(file, "http", {"SYSTEM":system}, rows=rows, instruction_limit=instruction_limit, operation=operation, phase=phase)

_PROFILES = {
    "secureboot": ("securebootai.dll", "C3294AD35CE6D6E6EBC6439C065A5FFB1", "aaac4b3adbc2f64c8a6b7d9dfd5155f1"),
    "fve": ("fveupdateai.dll", "6078D4184146ECF04107D2EDE2EF118F1", "bacf4a084f718a4da69afe4e9c8ce62d"),
    "http": ("httpai.dll", "2312C802846EF509E0355F875B1414A71", "1ae0fe864a95df11bc0ccea7dfd72085"),
    "timezone": ("timezoneai.dll", "F8ECBFA28DCD5DBE0D5ED7A282B221291", "d72c9b672bf9d64b8158db4520fa70e3"),
    "timezone-resource": ("timezoneai.dll", "F8ECBFA28DCD5DBE0D5ED7A282B221291", "2a702873068d40498cd5e33ddaffd52b"),
}

def run_basic_installer(file, profile, hives, rows=[], files={}, instruction_limit=500000, operation="install", phase=10):
    """Execute an identity-qualified basic installer for supported install/uninstall phases under explicit instruction limits; return native outcomes and effects."""
    if (operation,phase) not in [("install",10),("uninstall",8)]:
        fail("unsupported native basic-installer operation/phase")
    module_name, codeview, identifier = _PROFILES[profile]
    system = hives["SYSTEM"]
    pe = windows.pe(file)
    if pe.info["machine"] != 0x8664 or pe.codeview == None or pe.codeview["key"] != codeview:
        fail("CSI adapter requires the inspected 26100.9703 installer ABI")
    if type(instruction_limit)!="int" or instruction_limit<1 or instruction_limit>500000:
        fail("invalid CSI instruction bound")
    if len(rows)>4096: fail("CSI CDF table exceeds bound")
    for row in rows:
        if sorted(row)!=["sddl","url"] or any([type(v)!="string" or chr(0) in v or len(binary.encode(v,encoding="utf16le"))>65532 for v in row.values()]):
            fail("invalid CSI CDF string input")
    select = system.find("/Select")
    current = None if select==None else select.values.get("Current")
    if type(current) != "int" or current < 1 or current > 999 or select.value_records["Current"].type!=4:
        fail("invalid CSI offline control set")
    control = "ControlSet" + ("00" + str(current))[-3:]
    state = dict(objects={}, strings={}, blobs={}, enumerators={}, allocations={}, patches=[], calls=[], next_object=0, installer=0, registry_values={}, blob_allocations={}, value_deletions=[])

    def allocate(m, data, name):
        p = m.allocate(size=max(1,len(data)), name=name)
        m.write(p,data)
        return p

    def lstring(m, p):
        size = m.read_u64le(p)
        maximum = m.read_u64le(p+8)
        if size > maximum or size > 65534 or size % 2:
            fail("invalid CSI LUNICODE_STRING")
        return binary.text(m.read(m.read_pointer(p+16), size), encoding="utf16le")

    def key_location(path):
        parts = path.replace(chr(92),"/").strip("/").split("/")
        if [p.lower() for p in parts[:2]] != ["registry","machine"] or len(parts)<3 or parts[2].upper() not in hives:
            fail("CSI registry mount not admitted: " + path)
        hive = parts[2].upper()
        if hive=="SYSTEM" and len(parts)>3 and parts[3].lower()=="currentcontrolset": parts[3]=control
        return hive, "/" + "/".join(parts[3:])

    def key_path(path):
        hive, key = key_location(path)
        if hives[hive].find(key)==None:
            fail("CSI key creation requires inherited security: " + key)
        return key

    def object(m, kind, methods, data=None, count=24):
        number=state["next_object"]
        state["next_object"]+=1
        table=m.allocate(size=count*8,name=kind+" vtable")
        pointer=m.allocate(size=8,name=kind)
        m.write_pointer(pointer,table)
        state["objects"][pointer]=dict(kind=kind,data=data,refs=1)
        def unsupported(e):
            fail("unsupported CSI method: %s %s args=%s" % (kind,e.name,e.args))
        for slot in range(count):
            callback,argc=methods.get(slot,(unsupported,1))
            address=m.provide_export(callback,module="trex.csi",name="%s_%d_%d"%(kind,number,slot),argc=argc)
            m.write_pointer(table+slot*8,address)
        return pointer

    def release(e):
        obj=state["objects"][e.args[0]]
        if obj["refs"]<1: fail("CSI release after final reference")
        obj["refs"]-=1
        return obj["refs"]

    def add_ref(e):
        state["objects"][e.args[0]]["refs"]+=1
        return state["objects"][e.args[0]]["refs"]

    def malloc_free(e):
        if e.args[1]:
            if e.args[1] not in state["allocations"]: fail("CSI allocator does not own pointer")
            e.machine.free(e.args[1])
            state["allocations"].pop(e.args[1])
        return 0

    def registry_open(e):
        # CreateOptions 4 is backup/restore intent. Only already present keys
        # are admitted; no creation, security inheritance or link follows.
        m,a=e.machine,e.args
        if a[1]!=1 or (a[4]&0xffffffff) not in [0,4] or m.read_u64le(a[3])!=40 or m.read_u32le(a[3]+16) not in [0,0x40]:
            fail("unsupported CSI relative-key options: %s attrs=%s" % (a,hex(m.read(a[3],40))))
        parent=state["objects"][a[0]]["data"]
        path=parent+"/"+lstring(m,m.read_pointer(a[3]+8))
        key_path(path)
        m.write_pointer(a[5],new_key(m,path))
        if a[6]: m.write_u32le(a[6],2)
        return 0

    def registry_set(e):
        m,a=e.machine,e.args
        if a[1]!=0 or a[6]!=0 or a[5]>1048576:
            fail("unsupported CSI registry value options")
        path=key_path(state["objects"][a[0]]["data"])
        name=lstring(m,a[2])
        raw=m.read(a[4],a[5])
        hive = key_location(state["objects"][a[0]]["data"])[0]
        state["registry_values"][(hive,path.lower(),name.lower())]=(a[3]&0xffffffff,raw)
        patch=dict(key=path,name=name,type=a[3]&0xffffffff,raw=raw)
        if profile!="http": patch["hive"]=hive
        state["patches"].append(patch)
        return 0

    def registry_delete(e):
        # Pinned CKey::DeleteValue slot 24; HTTPAI requests ignore-not-found
        # with no disposition output. The effect remains isolated until commit.
        m,a=e.machine,e.args
        if profile!="http" or operation!="uninstall" or phase!=8 or a[1]!=1 or a[3]!=0:
            fail("unsupported CSI delete-value options")
        path=state["objects"][a[0]]["data"]
        hive,key=key_location(path)
        key_path(path)
        name=lstring(m,a[2])
        if len(state["value_deletions"])>=4096: fail("CSI deletion table exceeds bound")
        state["registry_values"][(hive,key.lower(),name.lower())]=None
        state["value_deletions"].append(dict(hive=hive,key=key,name=name))
        return 0

    def registry_open_existing(e):
        m,a=e.machine,e.args
        if a[1] not in [0,1] or m.read_u64le(a[3])!=40 or m.read_u32le(a[3]+16)!=0x40:
            fail("unsupported CSI existing-key options")
        path=state["objects"][a[0]]["data"]+"/"+lstring(m,m.read_pointer(a[3]+8))
        hive,key=key_location(path)
        exists=hives[hive].find(key)!=None
        m.write_pointer(a[4],new_key(m,path) if exists else 0)
        m.write_u32le(a[5],1 if exists else 2)
        return 0

    def registry_query(e):
        m,a=e.machine,e.args
        if a[1]!=1 or a[3] not in [1,2]: fail("unsupported CSI value-query options: "+str(a))
        hive,key=key_location(state["objects"][a[0]]["data"])
        name=lstring(m,a[2])
        identity=(hive,key.lower(),name.lower())
        value=state["registry_values"].get(identity)
        if identity not in state["registry_values"]:
            node=hives[hive].find(key)
            for n,r in node.value_records.items():
                if n.lower()==name.lower(): value=(r.type,r.raw)
        if value==None:
            m.write_u32le(a[5],1)
            return 0
        if a[3]==2:
            data=binary.concat([binary.u32le(0),binary.u32le(value[0]),binary.u32le(len(value[1])),value[1]]).bytes()
        else:
            encoded=binary.encode(name,encoding="utf16le")
            offset=(20+len(encoded)+3)&~3
            data=binary.concat([binary.u32le(0),binary.u32le(value[0]),binary.u32le(offset),binary.u32le(len(value[1])),binary.u32le(len(encoded)),encoded,b"\x00"*(offset-20-len(encoded)),value[1]]).bytes()
        p=allocate(m,data,"CSI registry value information")
        state["blob_allocations"][p]=True
        m.write_u64le(a[4],len(data))
        m.write_u64le(a[4]+8,len(data))
        m.write_pointer(a[4]+16,p)
        m.write_u32le(a[5],2)
        return 0

    def free_blob(e):
        m,p=e.machine,e.args[0]
        data=m.read_pointer(p+16)
        if data:
            if data not in state["blob_allocations"]: fail("CSI blob allocator does not own pointer")
            m.free(data)
            state["blob_allocations"].pop(data)
        m.write(p,b"\x00"*24)
        return 0

    def enumerate_next(e):
        m,a=e.machine,e.args
        obj=state["objects"][a[0]]["data"]
        array=m.read_pointer(a[1])
        capacity=m.read_u64le(a[1]+8)
        if capacity>4096: fail("CSI key enumeration exceeds bound")
        batch=obj["names"][obj["index"]:obj["index"]+capacity]
        for index,name in enumerate(batch):
            data=binary.encode(name,encoding="utf16le")
            text=allocate(m,data,"CSI enumerated key name")
            descriptor=m.allocate(size=24,name="CSI enumerated LUNICODE_STRING")
            m.write_u64le(descriptor,len(data))
            m.write_u64le(descriptor+8,len(data))
            m.write_pointer(descriptor+16,text)
            m.write_pointer(array+index*8,descriptor)
        obj["index"]+=len(batch)
        m.write_u64le(a[2],len(batch))
        return 0

    def enumerate_keys(e):
        m,a=e.machine,e.args
        if a[1]!=0: fail("unsupported CSI key enumeration flags")
        hive,key=key_location(state["objects"][a[0]]["data"])
        names=[child.name for child in hives[hive].find(key).children]
        pointer=object(m,"IRtlKeyNameEnumerator",{0:(release,1),2:(enumerate_next,3)},data=dict(names=names,index=0))
        m.write_pointer(a[2],pointer)
        return 0

    def new_key(m,path):
        return object(m,"IRtlKey",{0:(release,1),7:(registry_open,7),13:(registry_open_existing,6),19:(registry_query,6),21:(registry_set,7),24:(registry_delete,4),25:(enumerate_keys,3)},data=path,count=32)

    def open_absolute(e):
        # Native SIL flag 2 is OpenForBackupIntent. Offline privileged reads
        # still require the exact existing key; absent keys remain errors.
        m,a=e.machine,e.args
        if (a[1],bool(a[5])) not in [(0,False),(2,False),(3,True)]: fail("unsupported CSI absolute-key options: %s %s"%(a,lstring(m,a[3])))
        path=lstring(m,a[3])
        key_path(path)
        m.write_pointer(a[4],new_key(m,path))
        if a[5]: m.write_u32le(a[5],1)
        return 0

    def get_root(e):
        if profile!="http": fail("CDF input is not implemented for this installer profile")
        e.machine.write_u32le(e.args[1],1)
        return 0

    def get_section(e):
        if list(e.args[1:4]) != [0,1,0x22]: fail("unsupported CSI CDF section")
        e.machine.write_u32le(e.args[4],2)
        return 0

    def get_string(e):
        m,a=e.machine,e.args
        text=state["strings"].get(a[1])
        if text==None: fail("unknown CSI CDF string")
        p=allocate(m,binary.encode(text+chr(0),encoding="utf16le"),"CDF string")
        state["allocations"][p]=True
        m.write_pointer(a[2],p)
        return 0

    def get_blob(e):
        m,a=e.machine,e.args
        data=state["blobs"].get(a[1])
        if data==None: fail("unknown CSI CDF data")
        m.write_u64le(a[2],len(data))
        m.write_pointer(a[3],allocate(m,data,"CDF data"))
        return 0

    def next_item(e):
        m,a=e.machine,e.args
        if a[1]!=1: fail("unsupported CSI CDF enumeration count")
        index=state["enumerators"][a[0]]
        if index==len(rows):
            m.write_u64le(a[3],0)
            return 1
        m.write_u32le(a[2],index*2+1)
        m.write_u32le(a[2]+4,index+1)
        m.write_u64le(a[3],1)
        state["enumerators"][a[0]]=index+1
        return 0

    def enum_table(e):
        m,a=e.machine,e.args
        if list(a[1:3])!=[0,2]: fail("unsupported CSI CDF enumeration")
        p=object(m,"ICDFEnumerator",{1:(add_ref,1),2:(release,1),3:(next_item,4)})
        state["enumerators"][p]=0
        m.write_pointer(a[3],p)
        return 0

    def unsupported_wcp(e):
        fail("unsupported WCP service: %s args=%s"%(e.name,e.args))

    def trace_message(e):
        if len(state["calls"])>=64: fail("CSI trace-message bound exceeded")
        state["calls"].append(dict(kind="trace",flags=e.args[:2],format=e.machine.read_cstring(e.args[3],encoding="ascii")))
        return 0

    def tracing_disabled(e):
        return 0

    def init_lstring(e):
        m,a=e.machine,e.args
        text=m.read_cstring(a[0],encoding="utf16le")
        size=len(binary.encode(text,encoding="utf16le"))
        m.write_u64le(a[1],size)
        m.write_u64le(a[1]+8,size+2)
        m.write_pointer(a[1]+16,a[0])
        return 0

    def locale_name(e):
        m,a=e.machine,e.args
        if a[0]!=0x409 or a[3]!=0: fail("CSI locale inventory admits only en-US without flags")
        if a[2]==0: return 6
        if a[2]<6 or not a[1]: fail("CSI locale output buffer is too small")
        m.write(a[1],binary.encode("en-US"+chr(0),encoding="utf16le"))
        return 6

    def install(m):
        if profile.startswith("timezone"):
            m.provide_export(locale_name,module="api-ms-win-core-localization-obsolete-l1-2-0.dll",name="LCIDToLocaleName",argc=4)
        # Explicit logging policy; no installer effect or error is suppressed.
        for entry in pe.imports:
            if entry["dll"].lower()!="wcp.dll": continue
            name=entry["name"]
            cb,argc=(unsupported_wcp,1)
            if name.startswith("?RtlGetFacilityTracingFlags"): cb,argc=tracing_disabled,1
            if name.startswith("?RtlTraceVa@"): cb,argc=trace_message,6
            if name=="RtlInitLUnicodeStringFromNullTerminatedString": cb,argc=init_lstring,2
            if name=="RtlFreeLBlob": cb,argc=free_blob,1
            if name=="RtlReportErrorOrigination": cb,argc=unsupported_wcp,3
            m.provide_export(cb,module="wcp.dll",name=name,argc=argc)

    plugin=emulator.plugin(install,name="windows.csi",state=state)

    def execute(m):
        iid=allocate(m,_BASIC_IID,"ICSIBasicInstaller IID")
        clsid=allocate(m,binary.decode(identifier,"hex"),"CSI installer identifier")
        output=m.allocate(size=8,name="installer output")
        result=m.call_export("DllCsiGetHandler",args=[clsid,iid,output])
        if result.reason!="return" or result.value!=0:
            fail("CSI handler creation failed: %s %s %s" % (result.reason,result.value,result.detail))
        pointer=m.read_pointer(output)
        state["installer"]=pointer
        allocator=object(m,"IMalloc",{1:(add_ref,1),2:(release,1),5:(malloc_free,2)})
        sil=object(m,"IRtlSystemIsolationLayer",{0:(release,1),5:(open_absolute,6)})
        def get_allocator(e):
            state["objects"][allocator]["refs"]+=1
            e.machine.write_pointer(e.args[1],allocator)
            return 0
        def get_sil(e):
            state["objects"][sil]["refs"]+=1
            e.machine.write_pointer(e.args[1],sil)
            return 0
        def expand_path(e):
            m,a=e.machine,e.args
            text=m.read_cstring(a[2],encoding="utf16le")
            if a[1]!=1 or a[4]!=0: fail("unsupported CSI path expansion flags")
            text=expand_csi_windows_path(text)
            m.write_pointer(a[3],allocate(m,binary.encode(text+chr(0),encoding="utf16le"),"expanded CSI path"))
            return 0
        services=object(m,"ICSIInstallerServices",{3:(get_allocator,2),5:(expand_path,5),16:(get_sil,2)})
        cdf=object(m,"ICDF",{3:(get_root,2),4:(get_string,3),6:(get_blob,4),11:(enum_table,4),18:(get_section,5)})
        for index,row in enumerate(rows):
            state["strings"][index*2+1]=row["url"]
            state["strings"][index*2+2]=row["sddl"]
            state["blobs"][index+1]=binary.u32le(index*2+2)
        component=m.allocate(size=128,name="CSI_INSTALLER_COMPONENT_INFO")
        m.write_pointer(component+8,cdf)
        success=m.allocate(size=4,name="installer success")
        result=m.call(m.read_pointer(m.read_pointer(pointer)+(24 if operation=="install" else 32)),args=[pointer,0,0,services,component,0,phase,success])
        if result.reason!="return" or result.value!=0 or m.read_u32le(success)!=1:
            fail("CSI %s phase %d did not complete: %s value=%s pc=%s steps=%s detail=%s writes=%d" % (operation,phase,result.reason,result.value,hex(result.pc),result.steps,result.detail,len(state["patches"])))
        released=m.call(m.read_pointer(m.read_pointer(pointer)+16),args=[pointer])
        if released.reason!="return" or released.value!=0:
            fail("CSI installer release did not complete")
        unloaded=m.call_export("DllCanUnloadNow")
        if unloaded.reason!="return" or unloaded.value!=0 or state["allocations"] or state["blob_allocations"]:
            fail("CSI installer retained objects or allocator buffers")
        return result

    result=native_run(file,module_name,execute=execute,plugins=[plugin],files=files,initialize=True,instruction_limit=instruction_limit,memory_limit=64<<20)
    if result["result"].reason!="return" or result["result"].value!=0:
        fail("native CSI initialization failed: %s %s" % (result["result"].reason,result["result"].detail))
    for field in ["patches","registry_key_deletions","generated_entries","setup_actions","advpack_actions","service_activations","network_actions","process_queries","exceptions"]:
        if result[field]: fail("native CSI produced unhandled effects: "+field)
    if any([result["registry_effects"][k] for k in ["keys","key_deletions","values","value_deletions"]]):
        fail("native CSI produced unhandled registry effects")
    return dict(operation=operation,phase=phase,value_deletions=state["value_deletions"],patches=state["patches"],result=result["result"],initialization=result["initialization"],security_actions=result["security_actions"])


def basic_jobs_from_queue(queue,profile,changes):
    """Bind native phase-8 removal and phase-10 installation entries to inputs.

    This preserves native queue order and both identity references. It does not
    infer executor eligibility, inspect smart installers or declare a phase done.
    """
    if not queue.get("finalized",False): fail("native basic installer requires a finalized queue")
    identifier=_PROFILES[profile][2]
    jobs=[]
    previous=0
    for entry in queue["entries"]:
        if entry["installer"]!=identifier: continue
        phase,operation=entry["phase"],entry["operation"]
        if entry["flags"]!=0 or entry["inspect"]!=None or (phase,operation) not in [(8,1),(10,3)] or phase<previous:
            fail("unsupported native basic-installer entry or phase order")
        previous=phase
        sources={}
        indexes=[]
        for side in ["before","after"]:
            reference=entry[side]
            if reference==None:
                sources[side]=None
                continue
            index,label=reference
            if type(index)!="int" or index<0 or index>=len(changes) or label!=side:
                fail("invalid native basic-installer identity reference")
            source=changes[index][int(side=="after")]
            if source==None: fail("native basic-installer references an absent manifest")
            sources[side]=source
            indexes.append(index)
        if len(indexes)==2 and indexes[0]!=indexes[1]: fail("native basic-installer mixed change pairs")
        side="before" if operation==1 else "after"
        if sources[side]==None: fail("native basic-installer operation has no source")
        jobs.append(dict(operation="uninstall" if operation==1 else "install",phase=phase,manifest=sources[side],before=sources["before"],after=sources["after"]))
    return jobs
