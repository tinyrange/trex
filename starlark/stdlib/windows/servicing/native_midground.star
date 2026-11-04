"""Execute the pinned native service-category merger on explicit queue inputs.

This does not execute online ServicesSmartInstaller or publish any effects.
"""
load("@stdlib//windows/emulation:runner.star", native_run="run")

def service_category_jobs(queue,changes,inspect_manifests):
    """Bind native service-category queue entries to explicit changed and inspection manifests, preserving queue order."""
    if not queue.get("finalized",False) or queue["inspection_required"] and not queue["inspection_inventory_supplied"]:
        fail("native service category requires complete finalized queue")
    def source(ref,side=None):
        if ref==None: return None
        index,actual=ref
        if type(index)!="int" or index<0 or side!=None and actual!=side: fail("invalid service-category identity reference")
        if actual=="inspect":
            if index>=len(inspect_manifests): fail("service-category inspection index out of bounds")
            return inspect_manifests[index]
        if actual not in ["before","after"] or index>=len(changes): fail("service-category change index out of bounds")
        value=changes[index][int(actual=="after")]
        if value==None: fail("service-category references absent manifest")
        return value
    jobs=[]
    for entry in queue["entries"]:
        if entry["installer"]!="2c10a69c378b534b9acc4e2ec0217057": continue
        if entry["phase"]!=3 or entry["flags"]!=0: fail("unsupported service-category phase or flags")
        if entry["operation"]==2:
            if entry["inspect"]!=None or entry["before"]==None and entry["after"]==None: fail("invalid service-category delta")
            jobs.append((source(entry["before"],"before"),source(entry["after"],"after"),None))
        elif entry["operation"]==4:
            if entry["before"]!=None or entry["after"]!=None or entry["inspect"]==None: fail("invalid service-category inspection")
            jobs.append((None,None,source(entry["inspect"])))
        else: fail("unsupported service-category operation")
    return jobs

def run_native_service_category(wcp_file,hives,jobs,instruction_limit=500000000,token_privileges=None):
    """Run the qualified native service-category implementation with explicit hives, jobs and token privileges under an instruction bound."""
    if hex(digest(wcp_file,algorithm="sha256"))!="1a5d390bfbf10e24f124fd423916d15e00af06b7b8a6c982ca00ac1fd7991d85": fail("native service category requires pinned WCP")
    if sorted(hives)!=["SOFTWARE","SYSTEM"] or not jobs or len(jobs)>512 or instruction_limit<1 or instruction_limit>2000000000: fail("invalid native service-category bounds")
    if token_privileges==None: fail("native service category requires explicit servicing caller privileges")
    total=0
    for row in jobs:
        if len(row)!=3 or not any(row) or row[2]!=None and (row[0]!=None or row[1]!=None): fail("invalid service-category job")
        for f in row:
            if f!=None:
                if f.size>16<<20: fail("service-category manifest exceeds bound")
                total+=f.size
    if total>64<<20: fail("service-category input exceeds bound")
    state=dict(manifests={},parse_steps=0,callback_parse_steps=0,metrics=[],manifest_queries=0)
    def install(m): pass
    plugin=emulator.plugin(install,name="windows.csi.midground.services",state=state)
    def require(result,stage,status=True):
        if result.reason!="return" or status and result.value!=0:
            fail("native service category %s failed: %s value=%s steps=%s detail=%s"%(stage,result.reason,result.value,result.steps,result.detail))
    def execute(m):
        base=[v.base for v in m.modules if v.name=="wcp.dll"][0]
        held=[]
        data=m.allocate(size=24*len(jobs),name="native MidgroundInstallerChange array")
        for index,row in enumerate(jobs):
            for side,f in enumerate(row):
                if f==None: continue
                owner=m.allocate(size=8,name="midground manifest owner")
                require(m.call(base+0x64bcc,args=[owner]),"manifest allocation",False)
                manifest=m.read_pointer(owner)
                if not manifest: fail("null native service manifest")
                buf=m.allocate(value=f.bytes(),name="midground manifest bytes")
                blob=m.allocate(size=24,name="midground manifest LBLOB")
                m.write_u64le(blob,f.size)
                m.write_u64le(blob+8,f.size)
                m.write_pointer(blob+16,buf)
                parsed=m.call(base+0x114e30,args=[manifest,blob,0])
                require(parsed,"manifest parse")
                state["parse_steps"]+=parsed.steps
                identity=m.read_pointer(manifest+0x18)
                if not identity: fail("native service manifest has no identity")
                if identity in state["manifests"]: fail("duplicate native service manifest identity pointer")
                state["manifests"][identity]=(blob,side)
                m.write_pointer(data+index*24+side*8,identity)
                held.append((owner,manifest,buf,blob))
        def unsupported(e): fail("unsupported native midground callback: "+e.name)
        def manifest_query(e):
            blob,side=state["manifests"].get(e.args[1],(0,-1))
            if not blob or (e.name.endswith("_1") and side!=1) or (e.name.endswith("_2") and side not in [0,2]): fail("native midground manifest side mismatch")
            result=e.machine.invoke(base+0x114e30,args=[e.args[2],blob,0])
            require(result,"callback manifest parse")
            state["callback_parse_steps"]+=result.steps
            state["manifest_queries"]+=1
            return 0
        def architecture(e): return 9
        def metric(e):
            if len(state["metrics"])>=8: fail("native midground metric bound")
            state["metrics"].append(e.args[1])
            return None
        methods={1:(manifest_query,3),2:(manifest_query,3),3:(architecture,1),7:(metric,2)}
        table=m.allocate(size=8*8,name="midground callback vtable")
        callback=m.allocate(size=8,name="midground callback")
        m.write_pointer(callback,table)
        for slot in range(8):
            fn,argc=methods.get(slot,(unsupported,1))
            m.write_pointer(table+slot*8,m.provide_export(fn,module="trex.csi",name="midground_%d"%slot,argc=argc))
        sil_owner=m.allocate(size=8,name="native SIL owner")
        require(m.call(base+0x167f0,args=[0,0,sil_owner]),"native SIL")
        sil=m.read_pointer(sil_owner)
        vector=m.allocate(size=16,name="native midground change vector")
        m.write_pointer(vector,data)
        m.write_u64le(vector+8,len(jobs))
        # Flag zero is real apply mode. No native decision or merger is skipped.
        result=m.call(base+0x2f91b0,args=[0,vector,callback,sil])
        require(result,"merge")
        state["merge_steps"]=result.steps
        require(m.call(m.read_pointer(m.read_pointer(sil)),args=[sil]),"SIL release",False)
        for owner,manifest,buf,blob in held:
            require(m.call(base+0x4b2d0,args=[manifest]),"manifest destruction",False)
            require(m.call(base+0x33fb0,args=[manifest]),"manifest free",False)
            for allocation in [owner,buf,blob]: m.free(allocation)
        for allocation in [sil_owner,vector,data,table,callback]: m.free(allocation)
        state["manifests"].clear()
        state["completed"]=True
        return result
    report=native_run(wcp_file,"wcp.dll",execute=execute,plugins=[plugin],registry_hives=hives,user_name="SYSTEM",user_sid="S-1-5-18",token_privileges=token_privileges,initialize=True,instruction_limit=instruction_limit,memory_limit=512<<20)
    require(report["result"],"execution")
    if not state.get("completed",False): fail("native service category cleanup incomplete")
    for field in ["generated_entries","setup_actions","advpack_actions","service_activations","network_actions","process_queries","exceptions"]:
        if report[field]: fail("native service category unhandled effects: "+field)
    allowed_security=["rtlallocateandinitializesid","rtlcreatesecuritydescriptor","rtlsetownersecuritydescriptor","rtlsetgroupsecuritydescriptor","rtlgetcontrolsecuritydescriptor","rtlmakeselfrelativesd"]
    if any([action["api"] not in allowed_security for action in report["security_actions"]]): fail("native service category unhandled security operation")
    return dict(effects=report["registry_effects"],jobs=len(jobs),parse_steps=state["parse_steps"],callback_parse_steps=state["callback_parse_steps"],merge_steps=state["merge_steps"],manifest_queries=state["manifest_queries"],metrics=state["metrics"])
