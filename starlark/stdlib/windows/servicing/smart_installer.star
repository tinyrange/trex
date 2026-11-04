"""Execute pinned native CSI smart-installer jobs, without publishing effects.

The real WCP parser constructs manifest objects; each real installer DLL owns all
queue/commit decisions. This is not queue derivation or a CBS completion claim.
"""
load("@stdlib//windows/emulation:runner.star", native_run="run")
load("@stdlib//windows/emulation:native_exceptions.star", "native_exceptions_plugin")
load("@stdlib//windows/servicing:key_flags.star", "create_key_flags_registry")
load("@stdlib//windows/servicing:installer.star", "expand_csi_windows_path")
load("@stdlib//windows/servicing:native_runtime.star", "ntdll_runtime_plugin")
load("@stdlib//windows/servicing:native_lsa.star", "servicing_lsa_plugin")
load("@stdlib//windows/servicing:native_configuration.star", "query_native_installer_options")

_EVENTS_HASH = "1a147d18be10c3a15a86715c6b879501afa2052196755f74bbc55a5005e80869"
_WCP_HASH = "1a5d390bfbf10e24f124fd423916d15e00af06b7b8a6c982ca00ac1fd7991d85"

_SMART_PROFILES = {
    "per-user-registry": ("wcp.dll", _WCP_HASH, "7CC21FAF1E625E052DD8ADB23E8B25F21", "05ff0ff65c7cdd48a1d2b75aa14ad9b4"),
    "appx": ("appxreg.dll", "ff1aaee1cc2666bb79c819202c632d2788411d90b81ff07a000fbbc9325a8f56", "F25E496499992AB4FE78D62AFB7C1E4C1", "bab1aaf1e06e944dbaebc9fd61f365cf"),
    "network-drivers": ("NetSetupAI.dll", "61daae9a7d4f56a3ca2d27f2066a21a5a094b667fb30660331ced3d94b86584e", "1C0DA771859D6B5D2916B9DA027E312F1", "80f211a12359c0479a68d0bafb577901"),
    "events": ("EventsInstaller.dll", _EVENTS_HASH, "F96057FBF721AC7F9828B0E0494639A31", "2bfdb93b1e359c4bb1fced0758805998"),
    "system-protection": ("luainstall.dll", "68e7ac0efeee51f0bb8696e90425ebd257111ea94867428e733192293202dc80", "098A371F9F3502B168CD897616444CBA1", "a39bfc2ed6788c45ac190b5b6bdae296"),
}

def run_appx_installer(file, wcp_file, hives, jobs, token_privileges, instruction_limit=500000000):
    """Execute the bounded qualified AppX smart-installer profile with explicit token privileges and return native effects."""
    return run_smart_installer(file,wcp_file,"appx",hives,jobs,instruction_limit=instruction_limit,token_privileges=token_privileges)

def run_events_installer(file, wcp_file, hives, jobs, instruction_limit=20000000):
    """Execute the bounded qualified Events smart-installer profile against explicit hives and jobs; return native effects."""
    return run_smart_installer(file,wcp_file,"events",hives,jobs,instruction_limit=instruction_limit)

def run_system_protection_installer(file, wcp_file, hives, jobs, instruction_limit=20000000):
    """Execute the bounded qualified System Protection smart-installer profile and capture key-flag effects."""
    return run_smart_installer(file,wcp_file,"system-protection",hives,jobs,instruction_limit=instruction_limit)

def run_network_drivers_installer(file, wcp_file, netsetup_file, netsetup_engine_file, hives, jobs, instruction_limit=200000000, runtime=None):
    """Run the qualified network-driver smart profile with explicit NetSetup modules, hives, jobs and optional native runtime context."""
    return run_smart_installer(file,wcp_file,"network-drivers",hives,jobs,instruction_limit=instruction_limit,netsetup_file=netsetup_file,netsetup_engine_file=netsetup_engine_file,network_runtime=runtime)

def run_smart_installer(file, wcp_file, profile, hives, jobs, instruction_limit=20000000, netsetup_file=None, netsetup_engine_file=None, network_runtime=None,token_privileges=None,lsa_security=None,user_profile_sid=None,registry_hive_mounts=[],lsa_query_access=None):
    """Run explicit (operation, manifest-file) jobs and return uncommitted effects.

    Operations are native Install=1, Uninstall=2, Inspect=3. Callers must derive
    eligible jobs and offline phases independently. For per-user registry, the
    caller must supply the exact profile SID (empty for the default template),
    source-backed static mounts, local-policy read capability and caller token
    privileges. This executes one admitted profile; it does not enumerate users,
    establish phase eligibility or infer whether transaction POQs ran inline.
    No registry changes escape
    if initialization, parsing, queueing, commit, release or unload fails.
    """
    if profile=="per-user-registry":
        if type(user_profile_sid)!="bytes" or user_profile_sid and (len(user_profile_sid)<8 or binary.read_u8(user_profile_sid)!=1 or binary.read_u8(user_profile_sid,1)>15 or len(user_profile_sid)!=8+4*binary.read_u8(user_profile_sid,1)):
            fail("native per-user registry requires an explicit bounded profile SID; empty means default profile")
        if not registry_hive_mounts: fail("native per-user registry requires explicit source-hive mounts")
    elif lsa_security!=None or lsa_query_access!=None or user_profile_sid!=None or registry_hive_mounts:
        fail("per-user inputs are only valid for the per-user registry installer")
    module_name,module_hash,module_key,identifier=_SMART_PROFILES[profile]
    sources=[(file,module_hash,module_key),(wcp_file,_WCP_HASH,"7CC21FAF1E625E052DD8ADB23E8B25F21")]
    modules={} if profile=="per-user-registry" else {"wcp.dll":wcp_file}
    module_paths={}
    runtime_arguments={}
    runtime_plugins=[]
    native_exceptions=None
    lsa=None
    if profile=="per-user-registry":
        if lsa_security==None: fail("HKCU requires target LSA policy snapshot")
        lsa=servicing_lsa_plugin(lsa_security,query_access=lsa_query_access)
        runtime_plugins.append(lsa)
    if profile in ["appx","per-user-registry"]:
        if token_privileges==None: fail("native installer requires explicit servicing caller privileges")
        runtime_arguments=dict(user_name="SYSTEM",user_sid="S-1-5-18",token_privileges=token_privileges)
    if profile=="network-drivers":
        if network_runtime==None: fail("native Network Drivers requires prepare_network_runtime inputs")
        modules.update(network_runtime["modules"])
        native_exceptions=native_exceptions_plugin()
        runtime_plugins=[ntdll_runtime_plugin(),native_exceptions]
        runtime_arguments=dict(user_name="SYSTEM",user_sid="S-1-5-18",token_facts=network_runtime["token_facts"],object_directories=network_runtime["object_directories"],object_security_module="native-ntdll.dll",registry_creation_provider=network_runtime["registry_creation_provider"])
        if netsetup_file==None or netsetup_engine_file==None: fail("native Network Drivers requires target NetSetupApi.dll and NetSetupEngine.dll")
        sources.append((netsetup_file,"b3bc10c38783b2706ddf80962f2bbae0ea2521928cc6cea2612c815d1b542503","ABAFCC5675BF56659FBE517F0F078D321"))
        sources.append((netsetup_engine_file,"9adc8c385b1cd4ab832a9e0bb3af8fd90e19e5084cc573de9a377a9aef35f834","374A2198DFB249CB693E70317B324BB81"))
        modules["netsetupapi.dll"]=netsetup_file
        modules["netsetupengine.dll"]=netsetup_engine_file
        module_paths={name: "C:"+chr(92)+"Windows"+chr(92)+"System32"+chr(92)+leaf for name,leaf in [("netsetupapi.dll","NetSetupApi.dll"),("netsetupengine.dll","NetSetupEngine.dll")]}
        module_paths.update(network_runtime["module_paths"])
    elif netsetup_file!=None or netsetup_engine_file!=None or network_runtime!=None:
        fail("NetSetupApi input is only valid for Network Drivers")
    for source, expected, key in sources:
        pe=windows.pe(source)
        if hex(digest(source,algorithm="sha256"))!=expected or pe.info["machine"]!=0x8664 or pe.codeview==None or pe.codeview["key"]!=key:
            fail("native CSI smart installer adapter requires the inspected servicing and target binaries")
    if sorted(hives)!=["SOFTWARE","SYSTEM"] or not jobs or len(jobs)>(2048 if profile=="events" else 512) or instruction_limit<1 or instruction_limit>500000000:
        fail("invalid native CSI smart installer execution bounds")
    total=0
    for operation,manifest in jobs:
        if operation not in [1,2,3] or manifest.size>8<<20: fail("invalid native CSI smart installer job")
        total+=manifest.size
    if total>64<<20: fail("native CSI smart installer manifest batch exceeds bound")
    installer_options=query_native_installer_options(wcp_file,hives["SOFTWARE"]) if profile=="per-user-registry" else None
    state=dict(service_buffers={},wow_paths=[],manifest=0,allocations={},objects={},next_object=0,parse_steps=0,queue_steps=0,commit_steps=0)
    def require(result,stage,hresult=True):
        if result.reason!="return" or hresult and result.value!=0:
            fail("native CSI smart installer %s failed: %s value=%s pc=%s steps=%s detail=%s"%(stage,result.reason,result.value,hex(result.pc),result.steps,result.detail))
    def object(m,kind,methods,count=24):
        number=state["next_object"]
        state["next_object"]+=1
        table=m.allocate(size=count*8,name=kind+" vtable")
        pointer=m.allocate(size=8,name=kind)
        m.write_pointer(pointer,table)
        state["objects"][pointer]=dict(kind=kind,refs=1)
        def unsupported(e):
            fail("unsupported native CSI smart installer interface: "+kind+" "+e.name)
        for slot in range(count):
            callback,argc=methods.get(slot,(unsupported,1))
            address=m.provide_export(callback,module="trex.csi",name="%s_%d_%d"%(kind,number,slot),argc=argc)
            m.write_pointer(table+slot*8,address)
        return pointer
    def add_ref(e):
        state["objects"][e.args[0]]["refs"]+=1
        return state["objects"][e.args[0]]["refs"]
    def release(e):
        value=state["objects"][e.args[0]]
        if value["refs"]<1: fail("native CSI smart installer bridge release after final reference")
        value["refs"]-=1
        return value["refs"]
    def alloc(e):
        if e.args[1]>16<<20: fail("isolation allocation exceeds bound")
        pointer=e.machine.allocate(size=max(1,e.args[1]),name="CSI isolation allocator")
        state["allocations"][pointer]=True
        return pointer
    def free(e):
        if e.args[1]:
            if e.args[1] not in state["allocations"]: fail("native CSI smart installer allocator does not own pointer")
            e.machine.free(e.args[1])
            state["allocations"].pop(e.args[1])
        return None
    def virtual_path(e):
        m,a=e.machine,e.args
        path=m.read_cstring(a[2],encoding="utf16le")
        parts=path.split(chr(92))
        if a[1]!=1 or len(parts)<2 or [v.lower() for v in parts[:2]] not in [["hklm","software"],["hklm","system"]] or any([not p or p in [".",".."] for p in parts]) or len(path)>32767:
            fail("unsupported native CSI smart installer virtual path: flags=%s path=%s"%(a[1],path))
        # The isolated emulator mounts exactly these target hives. Its local
        # HKLM roots already denote the offline target, not a host registry.
        pointer=m.allocate(value=binary.encode(path,encoding="utf16le",nul=True),name="physical registry root")
        state["allocations"][pointer]=True
        state["service_buffers"][pointer]=True
        m.write_pointer(a[3],pointer)
        return 0
    def get_manifest(e):
        if profile=="per-user-registry": return state["objects"][e.args[0]]["manifest"]
        if not state["manifest"]: fail("native CSI smart installer used a released manifest")
        return state["manifest"]
    def install(m):
        pass
    plugin=emulator.plugin(install,name="windows.csi.smart",state=state)
    def execute(m):
        base=[v.base for v in m.modules if v.name=="wcp.dll"][0]
        iid=m.allocate(value=binary.decode("0db70ff14943d848b472668bc981f67f","hex"),name="ICSISmartInstaller IID")
        clsid=m.allocate(value=binary.decode(identifier,"hex"),name="CSI CLSID")
        output=m.allocate(size=8,name="CSI handler")
        require(m.call_export("DllCsiGetHandler",args=[clsid,iid,output]),"factory")
        pointer=m.read_pointer(output)
        table=m.read_pointer(pointer)
        def allocator_reference(e):
            # The Windows process allocator is immortal. Target combase's
            # CMalloc_AddRef and CMalloc_Release both execute `return 1`.
            # Keep strict ownership for allocated buffers and other objects.
            return 1
        allocator=object(m,"IMalloc",{1:(allocator_reference,1),2:(allocator_reference,1),3:(alloc,2),5:(free,2)})
        def get_allocator(e):
            e.machine.write_pointer(e.args[1],allocator)
            return 0
        def get_architecture(e):
            e.machine.write_u32le(e.args[1],9)  # Pinned AMD64 target.
            return 0
        def expand_path(e):
            mm,a=e.machine,e.args
            if a[1]!=1 or a[4]!=0 or not a[2] or not a[3]: fail("unsupported CSI path expansion arguments")
            text=expand_csi_windows_path(mm.read_cstring(a[2],encoding="utf16le"))
            pointer=mm.allocate(value=binary.encode(text,encoding="utf16le",nul=True),name="expanded CSI path")
            state["allocations"][pointer]=True
            mm.write_pointer(a[3],pointer)
            return 0
        service_methods={3:(get_allocator,2),4:(get_architecture,2),5:(expand_path,5),13:(virtual_path,4)}
        metadata_methods={3:(get_allocator,2),4:(get_architecture,2)}
        if profile in ["system-protection","network-drivers"]:
            # Register the actual allocator through WCP's exported API.
            require(m.call(base+0x1576a0,args=[allocator]),"SetIsolationIMalloc")
        if profile=="system-protection":
            def target_arch(e): return 9  # This pinned target is AMD64.
            store=object(m,"IRtlComponentStore",{6:(target_arch,1)})
            executor=m.allocate(size=0x268,name="WCP native WOW routing context")
            m.write_pointer(executor+0x260,store)
            local=m.allocate(size=0x28,name="WCP metadata routing context")
            m.write_pointer(local+0x20,executor)
            def redirect_wow(e):
                mm,a=e.machine,e.args
                if a[1]!=1 or not a[2] or not a[3] or not a[4]: fail("unsupported native WOW redirect arguments")
                # Native LocalInstallerServices -> QueueExecutor selects the
                # identity architecture and runs WCP's actual WOW rule table.
                result=mm.invoke(base+0xa0870,args=[local,a[1],a[2],a[3],a[4]])
                require(result,"native WOW redirect")
                output=mm.read_pointer(a[4])
                if output not in state["allocations"]: fail("WOW output not owned by isolation allocator")
                if len(state["wow_paths"])>=65536: fail("WOW path observation bound")
                state["wow_paths"].append((mm.read_cstring(a[3],encoding="utf16le"),mm.read_cstring(output,encoding="utf16le")))
                return result.value
            sil=create_key_flags_registry(m,hives,state,base+0x38630,base+0x33fb0)
            def get_system(e):
                e.machine.write_pointer(e.args[1],sil)
                return 0
            service_methods[16]=(get_system,2)
            metadata_methods={3:(get_allocator,2),6:(redirect_wow,5)}
        if profile in ["appx","per-user-registry"]:
            def get_native_system(e):
                # Match CQueueExecutor::GetTargetSystemLayer (1e83a8): a
                # queued filesystem plus buffered/queued registry providers.
                # The emulator roots already name the target, so no host-to-
                # target filesystem reroot is required. RtlGetSystem flags
                # select bitness, not backup/restore. Native QI gives each
                # caller an owned public reference; retain one private owner
                # for POQ enumeration after Commit.
                mm=e.machine
                if state.get("queued_sil"):
                    require(mm.invoke(base+0x1e5bec,args=[state["queued_sil"],e.args[1]]),"public queued target SIL")
                    return 0
                parent=mm.allocate(size=8)
                require(mm.invoke(base+0x167f0,args=[0,0,parent]),"parent SIL")
                layers=mm.allocate(size=96)
                mm.write_u32le(layers,2)
                mm.write_u32le(layers+32,3)
                mm.write_u32le(layers+64,2)
                constructor=mm.allocate(size=56)
                mm.write_pointer(constructor,mm.read_pointer(parent))
                mm.write_pointer(constructor+8,layers)
                mm.write_u64le(constructor+16,1)
                mm.write_pointer(constructor+24,layers+32)
                mm.write_u64le(constructor+32,2)
                owner=mm.allocate(size=8)
                require(mm.invoke(base+0x167f0,args=[0,constructor,owner]),"queued target SIL")
                require(mm.invoke(base+0x1e5bec,args=[mm.read_pointer(owner),e.args[1]]),"public queued target SIL")
                state["queued_sil"]=mm.read_pointer(owner)
                require(mm.invoke(base+0xf690,args=[parent]),"parent SIL release",False)
                for allocation in [parent,layers,constructor,owner]: mm.free(allocation)
                return 0
            service_methods[16]=(get_native_system,2)
        if profile=="per-user-registry":
            def internal_mobile(e): return 1 if installer_options["is_mobile_store"] else 0
            def internal_separated(e): return 1 if installer_options["state_separated"] else 0
            def internal_smi(e):
                e.machine.write_u32le(e.args[1],installer_options["values"]["smi_hive_updates"])
                return 0
            def internal_single(e):
                e.machine.write_u8(e.args[1],installer_options["values"]["single_resource_ownership"])
                return 0
            def internal_sku(e):
                mm=e.machine
                direct=mm.allocate(size=8)
                require(mm.invoke(base+0x167f0,args=[0,0,direct]),"direct target SIL for SKU query")
                result_slot=mm.allocate(value=binary.decode("a55a5a5a5a5a5a5a","hex"))
                # Initialize obtains the direct target SIL and calls the real
                # IsSkuAssembly(SIL,bool*), not an identity-name heuristic.
                require(mm.invoke(base+0xa42d0,args=[mm.read_pointer(direct),result_slot]),"native target SKU query")
                value=mm.read_u8(result_slot)
                if value not in [0,1] or hex(mm.read(result_slot+1,7))!="5a5a5a5a5a5a5a": fail("native SKU output invalid")
                require(mm.invoke(base+0xf690,args=[direct]),"SKU target SIL release",False)
                mm.free(direct)
                mm.free(result_slot)
                state["is_sku"]=value
                return value
            def internal_query(e):
                guid=hex(e.machine.read(e.args[1],16))
                if guid!="7ea16b6e3f5e424cbd2e11970d8ecd9a": fail("unsupported internal CSI service IID: "+guid)
                state["objects"][internal]["refs"]+=1
                e.machine.write_pointer(e.args[2],internal)
                return 0
            internal=object(m,"ICSIInstallerServicesInternal",{0:(internal_query,3),1:(add_ref,1),2:(release,1),3:(internal_mobile,1),4:(internal_smi,2),5:(internal_single,2),7:(internal_separated,1),8:(internal_sku,1)},count=10)
            service_methods[0]=(internal_query,3)
        if profile=="per-user-registry":
            if type(user_profile_sid)!="bytes": fail("native HKCU requires explicit profile SID bytes; empty denotes native default profile")
            def get_profile(e):
                mm=e.machine
                sid_pointer=mm.allocate(value=user_profile_sid) if user_profile_sid else 0
                result=mm.invoke(base+0xfc390,args=[state["queued_sil"],0,sid_pointer,e.args[1],0])
                if sid_pointer: mm.free(sid_pointer)
                require(result,"native explicit user profile")
                return 0
            service_methods[17]=(get_profile,2)
        services=object(m,"ICSIInstallerServices",service_methods)
        metadata=object(m,"ICSIMetadataInstallerServices",metadata_methods)
        manifest_interface=object(m,"IWcpManifest",{3:(get_manifest,1)},count=4)
        # Always call native Initialize. Events is a no-op; System Protection
        # retains these metadata services for Queue. Unknown methods stop.
        require(m.call(m.read_pointer(table+3*8),args=[pointer,metadata,1,0,0]),"initialize")
        cdf_inputs=[]
        retained_manifests=[]
        for operation,manifest in jobs:
            if profile=="network-drivers":
                data=manifest.bytes()
                buffer=m.allocate(value=data,name="CDF manifest input")
                blob=m.allocate(size=24,name="CDF LBLOB")
                m.write_u64le(blob,len(data))
                m.write_u64le(blob+8,len(data))
                m.write_pointer(blob+16,buffer)
                owner=m.allocate(size=8,name="IRtlCdf owner")
                parsed=m.call(base+0x26d550,args=[0,blob,0,0,owner])
                require(parsed,"CDF manifest parse")
                state["parse_steps"]+=parsed.steps
                raw=m.read_pointer(owner)
                cdf_output=m.allocate(size=8,name="ICDF owner")
                require(m.call(base+0x29b4a0,args=[raw,cdf_output]),"CDF COM wrapper")
                cdf=m.read_pointer(cdf_output)
                queued=m.call(m.read_pointer(table+6*8),args=[pointer,operation,cdf])
                require(queued,"CDF queue")
                state["queue_steps"]+=queued.steps
                # Retain native owners and borrowed XML through Commit/release.
                cdf_inputs.append((owner,blob,buffer,cdf_output,raw,cdf))
                continue
            owner=m.allocate(size=8,name="WcpManifest owner")
            # Native AutoNewPtr<WcpManifest>::Allocate and exported parser.
            allocated=m.call(base+0x64bcc,args=[owner])
            require(allocated,"manifest allocation",hresult=False)
            state["manifest"]=m.read_pointer(owner)
            if not state["manifest"]: fail("native WCP manifest allocation failed")
            data=manifest.bytes()
            buffer=m.allocate(value=data,name="manifest input")
            blob=m.allocate(size=24,name="LBLOB")
            m.write_u64le(blob,len(data))
            m.write_u64le(blob+8,len(data))
            m.write_pointer(blob+16,buffer)
            parsed=m.call(base+0x114e30,args=[state["manifest"],blob,0])
            require(parsed,"manifest parse")
            state["parse_steps"]+=parsed.steps
            if profile=="per-user-registry":
                manifest_interface=object(m,"IWcpManifestRetained",{1:(add_ref,1),2:(release,1),3:(get_manifest,1)},count=4)
                state["objects"][manifest_interface]["manifest"]=state["manifest"]
            queued=m.call(m.read_pointer(table+5*8),args=[pointer,operation,manifest_interface])
            require(queued,"queue")
            state["queue_steps"]+=queued.steps
            if profile=="per-user-registry":
                retained_manifests.append((state["manifest"],manifest_interface,owner,blob,buffer))
                require(m.call(m.read_pointer(m.read_pointer(manifest_interface)+16),args=[manifest_interface]),"caller manifest release",False)
                state["manifest"]=0
                continue
            # Queue owns its serialized input; native destruction/free here
            # also makes accidental later use of parser buffers fail closed.
            for target in [base+0x4b2d0,base+0x33fb0]:
                require(m.call(target,args=[state["manifest"]]),"manifest release",hresult=False)
            state["manifest"]=0
            for allocation in [owner,blob,buffer]: m.free(allocation)
        committed=m.call(m.read_pointer(table+7*8),args=[pointer,2,services])
        require(committed,"offline commit")
        state["commit_steps"]=committed.steps
        if profile in ["appx","per-user-registry"]:
            out=m.allocate(size=8)
            require(m.call(base+0xe9040,args=[state["queued_sil"],out]),"POQ iterator")
            iterator=m.read_pointer(out)
            count=m.call(base+0x236d50,args=[iterator])
            require(count,"POQ count",False)
            state["poq_count"]=count.value
            if count.value>4096: fail("native POQ bound")
            state["poq_seen"]=0
            state["poq_released"]=0
            def next_operation(e):
                mm=e.machine
                available=mm.invoke(base+0xfb840,args=[iterator])
                require(available,"POQ More",False)
                mm.write(e.args[3],b"\x00" if available.value else b"\x01")
                if available.value:
                    if state["poq_seen"]>=count.value: fail("native POQ count exceeded")
                    require(mm.invoke(base+0xf9c00,args=[iterator,e.args[2]]),"POQ Next")
                    state["poq_seen"]+=1
                return 0
            def release_operation(e):
                # Iterator payload is borrowed, and remains owned by the SIL.
                state["poq_released"]+=1
                return 0
            next_address=m.provide_export(next_operation,module="trex.csi",name="poq_next",argc=4)
            release_address=m.provide_export(release_operation,module="trex.csi",name="poq_release",argc=3)
            target=m.allocate(size=8)
            require(m.call(base+0x167f0,args=[0,0,target]),"POQ target SIL")
            # Match ApplyTransactionPOQsToSil's native acquisition vector:
            # Backup, Restore, Security and ManageVolume. Ownership comes
            # from the explicit caller inventory, never an implicit grant.
            privileges=m.allocate(size=16)
            vector=m.allocate(size=16)
            m.write_pointer(vector,base+0x407e40)
            m.write_u64le(vector+8,4)
            require(m.call(base+0x7e000,args=[privileges,vector]),"native POQ privileges")
            # The real executor chooses access, performs operations and
            # reports failures. Callbacks only enumerate borrowed native POQ
            # records; they do not interpret or replace any primitive.
            applied=m.call(base+0xb860c,args=[0,count.value,m.read_pointer(target),next_address,release_address,0,0,0,0,0,0,0])
            require(applied,"native POQ execution")
            require(m.call(base+0x7b880,args=[privileges]),"native POQ privilege restore")
            m.free(vector)
            m.free(privileges)
            state["poq_steps"]=applied.steps
            if state["poq_seen"]!=count.value or state["poq_released"]!=count.value: fail("native POQ traversal/ownership incomplete")
            require(m.call(base+0xf690,args=[target]),"POQ target release",False)
            m.free(target)
            require(m.call(m.read_pointer(m.read_pointer(iterator)),args=[iterator]),"POQ iterator release",False)
            require(m.call(m.read_pointer(m.read_pointer(state["queued_sil"])),args=[state["queued_sil"]]),"queued SIL release",False)
            m.free(out)
        require(m.call(m.read_pointer(table+2*8),args=[pointer]),"release")
        if profile in ["events","network-drivers","appx"]:
            require(m.call_export("DllCanUnloadNow"),"unload")
        if profile=="system-protection":
            if any([o["refs"] for o in state["key_flags_registry"]["objects"].values()]): fail("native installer retained registry interfaces")
        for manifest,interface,owner,blob,buffer in retained_manifests:
            if state["objects"][interface]["refs"]: fail("HKCU retained manifest interface after release")
            for target in [base+0x4b2d0,base+0x33fb0]: require(m.call(target,args=[manifest]),"retained manifest destruction",False)
            for allocation in [owner,blob,buffer,m.read_pointer(interface),interface]: m.free(allocation)
        for owner,blob,buffer,cdf_output,raw,cdf in cdf_inputs:
            require(m.call(m.read_pointer(m.read_pointer(cdf)+2*8),args=[cdf]),"CDF COM release",hresult=False)
            require(m.call(m.read_pointer(m.read_pointer(raw)),args=[raw]),"CDF release",hresult=False)
            for allocation in [owner,blob,buffer,cdf_output]: m.free(allocation)
        if profile in ["system-protection","network-drivers"]:
            require(m.call(base+0x1576a0,args=[0]),"clear isolation allocator")
        # NetSetupAI's native ControlSet path consumer retains the returned
        # allocation (14f9c..150de), even after Commit/Release/unload. Reclaim
        # only bridge-created service outputs at the execution boundary;
        # this does not substitute a native Free or forgive IMalloc leaks.
        for pointer in state["service_buffers"]:
            if pointer in state["allocations"]:
                m.free(pointer)
                state["allocations"].pop(pointer)
        if state["allocations"]: fail("native CSI smart installer retained allocator buffers")
        if native_exceptions!=None: native_exceptions.finish(m)
        return committed
    report=native_run(file,module_name,modules=modules,module_paths=module_paths,execute=execute,plugins=runtime_plugins+[plugin],registry_hives=hives,registry_hive_mounts=registry_hive_mounts,initialize=True,instruction_limit=instruction_limit,memory_limit=256<<20,**runtime_arguments)
    require(report["result"],"execution")
    for field in ["generated_entries","setup_actions","advpack_actions","service_activations","network_actions","process_queries","exceptions"]:
        if report[field]: fail("native CSI smart installer produced unhandled effects: "+field)
    allowed_security=["convertstringsecuritydescriptortosecuritydescriptorw", "addaccessallowedace", "copysid", "getlengthsid", "getsecuritydescriptorcontrol", "getsecuritydescriptorlength", "initializeacl", "initializesecuritydescriptor", "isvalidsecuritydescriptor", "ntqueryinformationtoken", "openprocesstoken", "openthreadtoken", "rtlgetappcontainernamedobjectpath", "setsecuritydescriptordacl"] if profile=="network-drivers" else ["convertstringsecuritydescriptortosecuritydescriptorw"]
    if profile in ["appx","per-user-registry"]:
        allowed_security += ["ntopenthreadtoken", "ntopenprocesstoken", "ntduplicatetoken", "ntadjustprivilegestoken", "adjusttokenprivileges", "setthreadtoken"]
    if profile=="per-user-registry":
        # These operate on caller-owned descriptor/SID buffers only. No ACL or
        # privilege publication is implied by permitting native conversions.
        allowed_security += ["rtlabsolutetoselfrelativesd", "rtlallocateandinitializesid", "rtlcreatesecuritydescriptor", "rtlgetcontrolsecuritydescriptor", "rtlinitializesid", "rtllengthsecuritydescriptor", "rtllengthsid", "rtlmakeselfrelativesd", "rtlsetdaclsecuritydescriptor", "rtlsetgroupsecuritydescriptor", "rtlsetownersecuritydescriptor", "rtlsetsaclsecuritydescriptor", "rtlsubauthoritycountsid", "rtlsubauthoritysid"]
        if lsa.state["handles"] or lsa.state["buffers"]: fail("native installer retained LSA policy ownership")
    if any([a["api"] not in allowed_security for a in report["security_actions"]]):
        fail("native CSI smart installer produced an unhandled security operation")
    return dict(poq_count=state.get("poq_count",0),poq_steps=state.get("poq_steps",0),native_raises=len(native_exceptions.state["raises"]) if native_exceptions!=None else 0,key_flags=state.get("key_flags_registry",{}).get("patches",[]),key_queries=state.get("key_flags_registry",{}).get("queries",0),wow_paths=state["wow_paths"],effects=report["registry_effects"],parse_steps=state["parse_steps"],queue_steps=state["queue_steps"],commit_steps=state["commit_steps"],jobs=len(jobs))


def smart_jobs_from_queue(queue,profile,changes,inspect_manifests=None):
    """Translate native phase-9 entries for an admitted smart-installer profile.

    WCP ExecuteSingle queues the new manifest as Install=1 first, then the old
    manifest as Uninstall=2. Commit resolves that aggregate; these calls are
    not immediate registry writes. Inspection uses its exact retained identity.
    """
    if not queue.get("finalized",False): fail("native smart installer requires a finalized queue")
    identifier=_SMART_PROFILES[profile][3]
    if queue["inspection_required"] and (not queue["inspection_inventory_supplied"] or inspect_manifests==None):
        fail("native smart installer jobs require the installed-component inspection inventory")
    def source(reference,expected=None):
        index,side=reference
        if type(index)!="int" or index<0 or expected!=None and side!=expected:
            fail("invalid native smart installer identity reference")
        if side=="inspect":
            if inspect_manifests==None or index>=len(inspect_manifests): fail("native smart installer inspection identity out of bounds")
            return inspect_manifests[index]
        if side not in ["before","after"] or index>=len(changes): fail("native smart installer changed identity out of bounds")
        result=changes[index][int(side=="after")]
        if result==None: fail("native smart installer references an absent manifest")
        return result
    jobs=[]
    for entry in queue["entries"]:
        if entry["installer"]!=identifier: continue
        if entry["phase"]!=9 or entry["flags"]!=0: fail("native smart installer entry has unsupported phase or flags")
        if entry["operation"]==2:
            if entry["inspect"]!=None or entry["after"]==None and entry["before"]==None:
                fail("invalid native smart installer delta entry")
            if entry["after"]!=None: jobs.append((1,source(entry["after"],"after")))
            if entry["before"]!=None: jobs.append((2,source(entry["before"],"before")))
        elif entry["operation"]==4:
            if entry["inspect"]==None or entry["after"]!=None or entry["before"]!=None:
                fail("invalid native smart installer inspect entry")
            jobs.append((3,source(entry["inspect"])))
        else:
            fail("unsupported native smart installer execution operation")
    return jobs
