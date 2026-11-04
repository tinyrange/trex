"""Derive phase 3..12 AI entries with the pinned native WCP implementation.

This returns an execution plan, not committed servicing state. It deliberately
uses the ordinary non-repair/non-debug flags (0) and no external transforms.
Explicit source/target hives permit bounded read-only transformer-state queries;
all other native environment operations stop execution.
"""
load("@stdlib//windows/emulation:runner.star", native_run="run")
load("@stdlib//windows/servicing:queue_registry.star", "create_queue_registry")

_WCP_HASH = "1a5d390bfbf10e24f124fd423916d15e00af06b7b8a6c982ca00ac1fd7991d85"

def derive_offline_queue(wcp_file, changes, inspect_manifests=None, instruction_limit=200000000, registry_snapshots=None, progress=None, progress_interval=256):
    """Return native finalized entries for explicit (old, new) manifest pairs.

    Omitted inspect_manifests explicitly leaves the installed inventory unknown.
    The returned inspection_required flag must not be treated as satisfied.
    Entry operation numbers belong to ExecutionQueueEntry, NOT the smart
    installer interface. Identity references are (input-index, side) pairs.
    Caller must still supply the complete inspection inventory, dispatch the
    native operation and execute/commit every applicable phase. Phases 60/61
    are outside this adapter. Inspection references index inspect_manifests.
    registry_snapshots is an explicit (before, after) pair of COMPONENTS/SYSTEM
    hive maps for native transformer admission; omission fails on any SIL read.
    progress, when supplied, receives bounded completed-input counts (every
    progress_interval inputs and at each stage end), not mutable emulator state
    or a partial queue. This interval does not change native queue decisions.
    Individual manifests are limited to 16 MiB, the total to 512 MiB, and each
    native call to the explicit instruction_limit (at most two billion).
    """
    pe=windows.pe(wcp_file)
    if hex(digest(wcp_file,algorithm="sha256"))!=_WCP_HASH or pe.info["machine"]!=0x8664 or pe.codeview==None or pe.codeview["key"]!="7CC21FAF1E625E052DD8ADB23E8B25F21":
        fail("native queue adapter requires the inspected 26100.9703 WCP")
    if not changes or len(changes)>8192 or instruction_limit<1 or instruction_limit>2000000000:
        fail("invalid native queue execution bounds")
    if type(progress_interval)!="int" or progress_interval<1 or progress_interval>4096:
        fail("invalid native queue progress interval")
    total=0
    for old,new in changes:
        if old==None and new==None: fail("empty native change pair")
        for f in [old,new]:
            if f!=None:
                if f.size>16<<20: fail("native queue manifest exceeds bound")
                total+=f.size
    if inspect_manifests!=None:
        if len(inspect_manifests)>32768: fail("native inspection inventory exceeds bound")
        for f in inspect_manifests:
            if f==None or f.size>16<<20: fail("invalid native inspection manifest")
            total+=f.size
    if total>512<<20: fail("native queue manifest batch exceeds bound")
    if registry_snapshots!=None and (len(registry_snapshots)!=2 or any([sorted(h)!=["COMPONENTS","SYSTEM"] for h in registry_snapshots])):
        fail("native queue requires (before, after) registry snapshots")
    state=dict(parse_steps=0,derive_steps=0,finalize_steps=0,entries=[],descriptors={},inspection_required=False,inspection_inventory_supplied=inspect_manifests!=None)
    def install(m):
        pass
    plugin=emulator.plugin(install,name="windows.csi.queue",state=state)
    def execute(m):
        base=[v.base for v in m.modules if v.name=="wcp.dll"][0]
        def call(rva,args,stage,hresult=True):
            result=m.call(base+rva,args=args)
            if result.reason!="return" or hresult and result.value!=0:
                fail("native queue %s failed: %s value=%s pc=%s steps=%s detail=%s"%(stage,result.reason,result.value,hex(result.pc),result.steps,result.detail))
            return result
        def unsupported(e):
            fail("native queue requires an unimplemented target SIL operation: "+e.name)
        # No guessed filesystem/store answers when no explicit snapshots exist.
        table=m.allocate(size=64*8,name="queue SIL vtable")
        sil=m.allocate(size=8,name="queue SIL")
        m.write_pointer(sil,table)
        for slot in range(64):
            m.write_pointer(table+slot*8,m.provide_export(unsupported,module="trex.csi",name="queue_sil_%d"%slot,argc=1))
        before_sil,after_sil=sil,sil
        if registry_snapshots!=None:
            before_sil=create_queue_registry(m,registry_snapshots[0],state,"before",base+0x38630,base+0x33fb0)
            after_sil=create_queue_registry(m,registry_snapshots[1],state,"after",base+0x38630,base+0x33fb0)
        wrapper=m.allocate(size=16,name="ExecutionQueueDeriver")
        call(0x14b460,[wrapper,0,3,12,0,after_sil,before_sil,0],"initialize")
        impl=m.read_pointer(wrapper)
        descriptors=m.read_pointer(impl+0x68)
        count=m.read_u64le(impl+0x70)
        if count!=91: fail("native WCP installer descriptor count changed")
        for i in range(count):
            d=descriptors+i*80
            guid=hex(m.read(d,16))
            name=m.read_pointer(d+40)
            dll=m.read_pointer(d+48)
            if guid not in state["descriptors"]: state["descriptors"][guid]=[]
            state["descriptors"][guid].append(dict(name=m.read_cstring(name) if name else "",dll=m.read_cstring(dll,encoding="utf16le") if dll else "",flags=m.read_u32le(d+16),phase_mask=m.read_u64le(d+24)))
        identities={}
        work=[("change",index,pair) for index,pair in enumerate(changes)]
        if inspect_manifests!=None:
            work.extend([("inspect",index,(None,f)) for index,f in enumerate(inspect_manifests)])
        for kind,index,pair in work:
            if kind=="inspect" and not state["inspection_required"]: break
            manifests=[]
            allocations=[]
            for side,f in zip(["before","after"],pair):
                if f==None:
                    manifests.append(0)
                    continue
                owner=m.allocate(size=8,name="WcpManifest owner")
                call(0x64bcc,[owner],"manifest allocation",False)
                p=m.read_pointer(owner)
                if not p: fail("native WCP returned a null manifest")
                buf=m.allocate(value=f.bytes(),name="manifest input")
                blob=m.allocate(size=24,name="LBLOB")
                m.write_u64le(blob,f.size)
                m.write_u64le(blob+8,f.size)
                m.write_pointer(blob+16,buf)
                result=call(0x114e30,[p,blob,0],"parse %d %s"%(index,side))
                state["parse_steps"]+=result.steps
                identity=m.read_pointer(p+0x18)
                if not identity: fail("native WCP manifest has no identity")
                identities[identity]=(index,"inspect" if kind=="inspect" else side)
                manifests.append(p)
                allocations.extend([owner,blob,buf])
            # Native AddChange takes NEW then OLD, unlike our input pair.
            result=call(0x5efe0,[wrapper,manifests[1],manifests[0]],"AddChange %d"%index) if kind=="change" else call(0x5ecd0,[wrapper,manifests[1]],"AddInspect %d"%index)
            if kind=="change" and index==len(changes)-1:
                state["inspection_required"]=bool(call(0x15d330,[wrapper],"ShouldRunInspect",False).value&255)
            state["derive_steps"]+=result.steps
            for p in manifests:
                if p:
                    call(0x4b2d0,[p],"manifest destruction",False)
                    call(0x33fb0,[p],"manifest free",False)
            for allocation in allocations: m.free(allocation)
            stage_total=len(changes) if kind=="change" else len(inspect_manifests)
            if progress!=None and ((index+1)%progress_interval==0 or index+1==stage_total):
                progress(dict(stage=kind,completed=index+1,total=stage_total,parse_steps=state["parse_steps"],derive_steps=state["derive_steps"]))
        output=m.allocate(size=16,name="execution vector")
        disposition=m.allocate(size=4,name="queue disposition")
        result=call(0x5c930,[wrapper,output,disposition],"finalize")
        state["finalize_steps"]=result.steps
        data=m.read_pointer(output)
        count=m.read_u64le(output+8)
        if count>131072: fail("native finalized queue exceeds bound")
        for i in range(count):
            p=data+i*0x70
            guid=hex(m.read(p,16))
            phase=m.read_u32le(p+0x14)
            if phase<3 or phase>12: fail("native queue escaped requested phase range")
            if guid not in state["descriptors"] or not any([d["phase_mask"]&(1<<phase) for d in state["descriptors"][guid]]):
                fail("native queue contains an unknown installer phase")
            offline=call(0x1181e0,[phase],"phase classification",False)
            if offline.value!=1: fail("native queue escaped offline phases")
            entry=dict(installer=guid,operation=m.read_u32le(p+0x10),phase=phase,flags=m.read_u32le(p+0x18))
            for field,offset in [("after",0x28),("before",0x20),("inspect",0x30)]:
                identity=m.read_pointer(p+offset)
                if identity and identity not in identities:
                    fail("native queue returned an unowned identity")
                entry[field]=identities[identity] if identity else None
            state["entries"].append(entry)
        call(0x52394,[output],"vector destruction",False)
        call(0x260750,[impl],"deriver destruction",False)
        for allocation in [output,disposition,wrapper,sil,table]: m.free(allocation)
        if registry_snapshots!=None:
            state["registry_queries"]={}
            for label,root_pointer in [("before",before_sil),("after",after_sil)]:
                bridge=state.pop(label)
                for pointer,obj in bridge["objects"].items():
                    if pointer!=root_pointer and obj["refs"]!=0: fail("native queue retained a registry key")
                    m.free(obj["table"])
                    m.free(pointer)
                state["registry_queries"][label]=bridge["queries"]
        state["finalized"]=True
        return result
    report=native_run(wcp_file,"wcp.dll",execute=execute,plugins=[plugin],initialize=True,instruction_limit=instruction_limit,memory_limit=512<<20)
    if not state.get("finalized",False) or report["result"].reason!="return" or report["result"].value!=0:
        fail("native WCP initialization or finalization did not complete")
    for field in ["generated_entries","setup_actions","advpack_actions","service_activations","network_actions","process_queries","exceptions","security_actions"]:
        if report[field]: fail("native queue derivation produced unexpected effects: "+field)
    if any(report["registry_effects"].values()): fail("native queue derivation modified registry state")
    return state
