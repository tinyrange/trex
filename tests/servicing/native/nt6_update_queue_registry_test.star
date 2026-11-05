"""Explicit-media controls for native WCP transformer registry queries."""
load("@stdlib//windows/emulation:runner.star", native_run="run")
load("@stdlib//windows/servicing:queue_registry.star", "create_queue_registry")

def verify_queue_registry(wcp):
    if hex(digest(wcp,algorithm="sha256"))!="1a5d390bfbf10e24f124fd423916d15e00af06b7b8a6c982ca00ac1fd7991d85":
        fail("queue registry regression requires inspected WCP")
    components=windows.hive_from_patches("COMPONENTS",[
        dict(key="/DerivedData/TransformSettingsVersion/Present",name="SettingsVersion",type="REG_DWORD",value=7),
        dict(key="/DerivedData/TransformSettingsVersion/WrongType",name="SettingsVersion",type="REG_SZ",value="7"),
        dict(key="/DerivedData/TransformSettingsVersion/MissingValue",name="Other",type="REG_DWORD",value=9),
    ])
    system=windows.hive_from_patches("SYSTEM",[
        dict(key="/Setup/BuildUpdate",name="Rollback",type="REG_DWORD",value=1),
        dict(key="/Setup/BuildUpdate",name="SourceOSVersion",type="REG_QWORD",value=0x000a000066bc24f1),
        dict(key="/Setup/BuildUpdate",name="TargetOSVersion",type="REG_QWORD",value=0x000a000066bc25ef),
    ])
    original=[digest(f) for f in [components,system]]
    state=dict(values={})
    def install(m): pass
    plugin=emulator.plugin(install,name="queue.registry.regression",state=state)
    def execute(m):
        base=[v.base for v in m.modules if v.name=="wcp.dll"][0]
        sil=create_queue_registry(m,{"COMPONENTS":windows.hive(components),"SYSTEM":windows.hive(system)},state,"test",base+0x38630,base+0x33fb0)
        def require(result):
            if result.reason!="return" or result.value!=0: fail("native registry query failed: "+str(result))
        for name,expected in [("Present",7),("WrongType",0),("MissingValue",0),("AbsentKey",0)]:
            data=binary.encode(name,encoding="utf16le")
            text=m.allocate(value=data,name="transform name")
            string=m.allocate(size=24,name="transform LUNICODE_STRING")
            m.write_u64le(string,len(data))
            m.write_u64le(string+8,len(data))
            m.write_pointer(string+16,text)
            out=m.allocate(value=binary.u32le(0xdeadbeef),name="settings output")
            require(m.call(base+0x263870,args=[sil,string,out,0]))
            actual=m.read_u32le(out)
            if actual!=expected: fail("native transform settings query mismatch: "+name+" "+str(actual))
            state["values"][name]=actual
            for p in [out,string,text]: m.free(p)
        versions=m.allocate(size=16,name="OS version outputs")
        result=m.call(base+0x26366c,args=[sil,versions,versions+8])
        require(result)
        actual=[m.read_u64le(versions),m.read_u64le(versions+8)]
        # Real WCP reverses source/target when Rollback is set. The query reuses
        # its LBLOB across the DWORD and QWORD reads, exercising native growth.
        if actual!=[0x000a000066bc25ef,0x000a000066bc24f1]: fail("native rollback version selection mismatch: "+str(actual))
        state["rollback_versions"]=actual
        m.free(versions)
        # An unimplemented SIL method must fail rather than pretend success.
        denied=m.call(m.read_pointer(m.read_pointer(sil)+6*8),args=[sil])
        if denied.reason!="plugin" or "unsupported read-only" not in denied.detail: fail("queue registry unsupported method was admitted")
        state["unsupported_rejected"]=True
        for pointer,obj in state["test"]["objects"].items():
            if pointer!=sil and obj["refs"]!=0: fail("native query leaked an IRtlKey reference")
            m.free(obj["table"])
            m.free(pointer)
        state["queries"]=state.pop("test")["queries"]
        state["completed"]=True
        return result
    report=native_run(wcp,"wcp.dll",execute=execute,plugins=[plugin],initialize=True,instruction_limit=100000,memory_limit=128<<20)
    if not state.get("completed",False): fail("native registry test did not execute")
    if any(report["registry_effects"].values()) or [digest(f) for f in [components,system]]!=original:
        fail("read-only queue registry modified its inputs")
    return state
