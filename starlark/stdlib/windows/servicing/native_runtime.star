"""Pinned servicing runtime boundary, not a replacement for native installer logic.

Map the target NTDLL under native-ntdll.dll. Only explicitly admitted public
exports are visible through ntdll.dll; native internal heap/token boundaries
use the emulator's owned process state. Optional feature-query status remains
the native result, not proof of the target system's effective feature policy.
"""

load("@stdlib//windows/emulation:runner.star",native_run="run")
load("@stdlib//windows:security.star","sid","acl","access_allowed_ace")

def ntdll_runtime_plugin():
    """Create the qualified native ntdll runtime plugin for emulation; this is not a host or booted-guest execution API."""
    native_exports = {"RtlNewSecurityObjectEx":8, "RtlDeleteSecurityObject":1,
        "SbSelectProcedure":4, "WinSqmIsOptedIn":0, "RtlQueryFeatureConfiguration":4}
    semantic_exports = {"RtlAllocateHeap":3, "RtlFreeHeap":3, "NtQueryInformationToken":5}
    def forwarding(target, name):
        def invoke(event):
            if name == "NtQueryInformationToken" and event.args[1] not in [4,5,6,10,25,41]:
                fail("native servicing runtime needs an unadmitted token class",event.args[1])
            result=event.machine.invoke(target,args=event.args)
            if result.reason!="return":
                fail("native servicing runtime boundary failed",name,result.reason,hex(result.pc),result.detail)
            return result.value
        return invoke
    def install(machine):
        images=[m for m in machine.modules if m.name=="native-ntdll.dll" and m.image_size]
        if len(images)!=1: fail("native servicing runtime requires a real target NTDLL image")
        image=images[0]
        def native_address(name):
            address=machine.resolve_export("native-ntdll.dll",name=name)
            if address < image.base or address >= image.base + image.image_size:
                fail("native servicing export did not resolve inside target NTDLL",name)
            return address
        # Resolve semantic delegates before exposing the admitted native exports.
        for name,argc in semantic_exports.items():
            target=machine.resolve_export("ntdll.dll",name=name)
            if not target or (target >= image.base and target < image.base + image.image_size):
                fail("native servicing boundary lacks a semantic implementation",name)
            machine.hook(forwarding(target,name),address=native_address(name),argc=argc)
        for name,argc in native_exports.items():
            machine.provide_export(forwarding(native_address(name),name),module="ntdll.dll",name=name,argc=argc)
        def unsupported_wnf(event):
            fail("native feature query requires target WNF state",hex(event.machine.read_u64le(event.args[0])))
        machine.hook(unsupported_wnf,address=native_address("NtQueryWnfStateData"),argc=6)
    return emulator.plugin(install,name="windows.servicing.native-ntdll")

# These inputs belong to the inspected Windows 11 target, not the host machine.
_RUNTIME_IMAGES = {
    "msvcrt.dll": ("/Windows/System32/msvcrt.dll", "fc1447db4e4814cbcb002179a8003a41f383fc417879f628727043cab8c25093", "FC0417B8DF754857A6826A24039CC49D1"),
    "ntdll.dll": ("/Windows/System32/ntdll.dll", "651ac9041af8e6b5ebd331d53163244c0a27d36d1433f0f15cac1f28c5f2e82c", "C031D45B0DA18A6E74D06ED6AB2DD9E11"),
    "smss.exe": ("/Windows/System32/smss.exe", "0d05e81c571aa03f1dde5e8fa40cef98b77e8eca64821ae4efab121983d81de6", "69DABD4999B5C5EDFF5FAABB0322FD351"),
    "ntoskrnl.exe": ("/Windows/System32/ntoskrnl.exe", "4a6af9a3dbbeb440c4a9fbe8a4d6832eae751ac3a85860d860b8313a737a2e3a", "B661C6FE72991D160FE37C48B8BC54701"),
    "rpcrt4.dll": ("/Windows/System32/rpcrt4.dll", "c060f02c11fb19c9c8a30b5077a87cdb17d4be40f08070a539ec73eb53402775", "98EB0270D0FF305F7ED48A570CFD4FF61"),
    "implatsetup.dll": ("/Windows/System32/ImplatSetup.dll", "e03a40172afc32344c947e5921f8b265aa8eaa65aee14cc4ba5364c660f7f87f", "F27443F4DC30125E4CF6B5B7428CB38B1"),
}

def prepare_network_runtime(root, system_hive):
    """Construct the isolated setup process's RPC directory, not a host ACL snapshot.

    SMSS supplies native creation security. Native NTDLL assigns an independent
    directory with no parent and default inheritance flags, using the target's
    directory generic mapping and verified SYSTEM token defaults. The resulting
    self-relative descriptor is queried by real RPC/NTDLL; it is never published
    into image registry security. This model does not claim the token or object
    namespace of a booted servicing process, nor effective feature-policy state.
    """
    files = {}
    names = root.path_names(lower=True)
    for name,(path,sha,key) in _RUNTIME_IMAGES.items():
        source=root.find(names.get(path.lower(),path))
        if source==None: fail("native network runtime input missing",path)
        image=windows.pe(source)
        if hex(digest(source,algorithm="sha256"))!=sha or image.info["machine"]!=0x8664 or image.codeview==None or image.codeview["key"]!=key:
            fail("native network runtime requires inspected target image",path)
        files[name]=source
    manager=system_hive.find("/ControlSet001/Control/Session Manager")
    if manager==None or manager.values.get("ProtectionMode")!=1 or chr(92)+"RPC Control" not in manager.values.get("ObjectDirectories",[]):
        fail("native network runtime requires the inspected SMSS directory policy")
    mapping=windows.pe(files["ntoskrnl.exe"]).read(0xc826b0,16)
    if mapping!=binary.decode("030002000c000200030002000f000f00","hex"):
        fail("native directory generic mapping differs from inspected kernel")
    facts={"owner":sid(5,[32,544]),"primary_group":sid(5,[18]),"integrity_level":16384,"process_trust_sid":b"",
        "default_dacl":acl([access_allowed_ace(sid(5,[18]),0x10000000),access_allowed_ace(sid(5,[32,544]),0xa0020000)],size=60)}
    state={}
    def install(machine):
        pass
    state_plugin=emulator.plugin(install,name="windows.servicing.namespace",state=state)
    def checked(result,stage):
        if result.reason!="return" or result.value:
            fail("native namespace "+stage,result.reason,hex(result.value),result.detail)
        return result
    def construct(machine):
        base=[m.base for m in machine.modules if m.primary][0]
        machine.write_u32le(base+0x31ce4,manager.values["ProtectionMode"])
        result=checked(machine.call(base+0x9d90,args=[1]),"SMSS constructor")
        descriptor=machine.read_pointer(base+0x32668)
        target=[m.base for m in machine.modules if m.name=="ntdll.dll"][0]+[e["rva"] for e in windows.pe(files["ntdll.dll"]).exports if e.get("name")=="RtlAbsoluteToSelfRelativeSD"][0]
        length=machine.allocate(size=4)
        sizing=machine.call(target,args=[descriptor,0,length])
        if sizing.reason!="return" or sizing.value!=0xc0000023: fail("native SMSS descriptor sizing")
        size=machine.read_u32le(length)
        if size<20 or size>4096: fail("native SMSS descriptor bound")
        output=machine.allocate(size=size)
        checked(machine.call(target,args=[descriptor,output,length]),"SMSS descriptor copy")
        state["creation"]=machine.read(output,machine.read_u32le(length))
        machine.free(output)
        machine.free(length)
        return result
    native_run(files["smss.exe"],"smss.exe",modules={"ntdll.dll":files["ntdll.dll"]},plugins=[state_plugin],execute=construct,initialize=False,instruction_limit=1000000,memory_limit=64<<20)
    def assign(machine):
        handle=machine.allocate(size=8)
        opened=machine.call(machine.resolve_export("advapi32.dll",name="OpenProcessToken"),args=[0xffffffffffffffff,8,handle])
        if opened.reason!="return" or opened.value!=1: fail("namespace process-token open")
        creation=machine.allocate(value=state["creation"])
        generic=machine.allocate(value=mapping)
        output=machine.allocate(size=8)
        result=checked(machine.call(machine.resolve_export("ntdll.dll",name="RtlNewSecurityObjectEx"),args=[0,creation,output,0,1,0,machine.read_pointer(handle),generic]),"directory assignment")
        descriptor=machine.read_pointer(output)
        length=machine.call(machine.resolve_export("native-ntdll.dll",name="RtlLengthSecurityDescriptor"),args=[descriptor])
        if length.reason!="return" or length.value<20 or length.value>4096: fail("native assigned descriptor bound")
        state["assigned"]=machine.read(descriptor,length.value)
        checked(machine.call(machine.resolve_export("ntdll.dll",name="RtlDeleteSecurityObject"),args=[output]),"directory descriptor release")
        closed=machine.call(machine.resolve_export("kernel32.dll",name="CloseHandle"),args=[machine.read_pointer(handle)])
        if closed.reason!="return" or closed.value!=1: fail("namespace process-token close")
        for pointer in [handle,creation,generic,output]: machine.free(pointer)
        return result
    native_run(files["smss.exe"],"smss.exe",modules={"native-ntdll.dll":files["ntdll.dll"]},plugins=[state_plugin,ntdll_runtime_plugin()],execute=assign,initialize=False,user_name="SYSTEM",user_sid="S-1-5-18",token_facts=facts,instruction_limit=1000000,memory_limit=64<<20)
    return {"modules":{"native-msvcrt.dll":files["msvcrt.dll"],"native-ntdll.dll":files["ntdll.dll"],"rpcrt4.dll":files["rpcrt4.dll"],"implatsetup.dll":files["implatsetup.dll"]},
        "registry_creation_provider":native_registry_creation_provider(root,facts),
        "token_facts":facts,"object_directories":{chr(92)+"RPC Control":{"access":0x20001,"security":state["assigned"]}},
        "module_paths":{name:"C:"+path.replace("/",chr(92)) for name,(path,sha,key) in _RUNTIME_IMAGES.items() if name in ["rpcrt4.dll","implatsetup.dll"]}}


def native_registry_creation_provider(root, facts):
    """Assign NULL-creator registry security with the pinned target kernel.

    This isolated, non-restricted SYSTEM subject uses the same explicit owner,
    group, default DACL and integrity facts as the network process. Native
    CmpCreateChild calls SeAssignSecurity(container=1, registry mapping, pool=1).
    No installer HRESULT, ACL inheritance decision or descriptor is synthesized.
    Explicit creators, class names and special create options remain unsupported.
    """
    path,sha,key=_RUNTIME_IMAGES["ntoskrnl.exe"]
    file=root.find(path)
    pe=windows.pe(file) if file!=None else None
    actual=hex(digest(file,algorithm="sha256")) if file!=None else ""
    server=actual=="a22c81e8c1507b42bce8d17181c3af9a9314c4b4d6dbaef6bf07e1aa3d179636"
    if server:
        key="B65A1E5D9D57D828E82F8C75F19E98571"
    if pe==None or (not server and actual!=sha) or pe.codeview==None or pe.codeview["key"]!=key:
        fail("native registry security requires inspected kernel")
    # Server 2025 26100.32230, independently executed against its real parent
    # key descriptor. Token field offsets and registry mapping are identical;
    # entry points and SID globals are not interchangeable across kernels.
    pool,free_pool,lock,unlock=(0xb680f0,0xb68cd0,0x2f0d80,0x20d8e0) if server else (0xb820f0,0xb82870,0x211bc0,0x25fa10)
    assign_rva,release_rva=(0x910e10,0xa20ce0) if server else (0x949590,0xa305a0)
    sid_globals=(0xe67788,0xe67850,0xf04968,0xe67848) if server else (0xe67d40,0xe67ce8,0xf05878,0xe67cf0)
    if facts["owner"]!=sid(5,[32,544]) or facts["primary_group"]!=sid(5,[18]) or facts["integrity_level"]!=16384 or facts["process_trust_sid"]!=b"":
        fail("native registry security requires the declared non-protected SYSTEM subject")
    expected_dacl=acl([access_allowed_ace(sid(5,[18]),0x10000000),access_allowed_ace(sid(5,[32,544]),0xa0020000)],size=60)
    if facts["default_dacl"]!=expected_dacl: fail("native SYSTEM default DACL differs")
    m=emulator.machine(image=pe.data,image_name="ntoskrnl.exe",instruction_limit=100000,memory_limit=128<<20,gs_base=0x10000000)
    base=m.modules[0].base
    thread=m.allocate(size=0x1000)
    m.write_pointer(0x10000188,thread)
    m.write_pointer(thread+0x98,thread+0x98)
    m.write_pointer(thread+0xa0,thread+0x98)
    state=dict(allocations={},locks=0,cache={},calls=0)
    resource=m.allocate(size=0x100)
    def allocate(e):
        flags,size,tag=e.args
        if flags not in [0x40,0x100] or tag not in [0x64536553,0x63416553] or size<20 or size>65536:
            fail("unexpected native security pool request",e.args)
        address=e.machine.allocate(size=size)
        state["allocations"][address]=(size,tag)
        return address
    def free(e):
        address,tag=e.args
        owned=state["allocations"].get(address)
        if owned==None or tag not in [0,owned[1]]: fail("unowned native security pool release")
        e.machine.free(address)
        state["allocations"].pop(address)
        return 0
    def acquire(e):
        if e.args!=[resource,1] or state["locks"]: fail("unexpected native token lock")
        state["locks"]=1
        return 1
    def release(e):
        if e.args!=[resource] or state["locks"]!=1: fail("unowned native token unlock")
        state["locks"]=0
        return 0
    def install(machine):
        for callback,rva,argc in [(allocate,pool,3),(free,free_pool,2),(acquire,lock,2),(release,unlock,1)]:
            machine.hook(callback,address=base+rva,argc=argc)
    m.use(emulator.plugin(install,name="windows.servicing.native-key-security",state=state))
    system=m.allocate(value=sid(5,[18]))
    admin=m.allocate(value=facts["owner"])
    integrity=m.allocate(value=sid(16,[facts["integrity_level"]]))
    groups=m.allocate(size=48)
    for index,address,attributes in [(0,system,7),(1,admin,15),(2,integrity,0x60)]:
        m.write_pointer(groups+index*16,address)
        m.write_u32le(groups+index*16+8,attributes)
    token=m.allocate(size=0x500)
    # These offsets are used by this exact kernel's RtlpNewSecurityObject and
    # integrity/trust helpers; default owner indexes the BA entry, not user SY.
    m.write_pointer(token+0x30,resource)
    m.write_u32le(token+0x90,1)
    m.write_pointer(token+0x98,groups)
    m.write_pointer(token+0xa8,system)
    m.write_pointer(token+0xb8,m.allocate(value=expected_dacl))
    m.write_u32le(token+0xd0,2)
    subject=m.allocate(size=32)
    m.write_pointer(subject+16,token)
    mapping=m.allocate(value=binary.decode("1900020006000200390002003f000f00","hex"))
    for rva,value in [(sid_globals[0],sid(3,[0])),(sid_globals[1],sid(3,[1])),(sid_globals[2],sid(16,[4096])),(sid_globals[3],sid(3,[4]))]:
        m.write_pointer(base+rva,m.allocate(value=value))
    def assign(parent):
        windows.security_descriptor_parts(parent)
        if parent in state["cache"]: return state["cache"][parent]
        if len(parent)>65536 or len(state["cache"])>=256: fail("native registry security input bound")
        if state["allocations"] or state["locks"] or m.read_u16le(thread+0x1e4): fail("unclean native key-security context")
        input=m.allocate(value=parent)
        output=m.allocate(size=8)
        result=m.call(base+assign_rva,args=[input,0,output,1,subject,mapping,1])
        if result.reason!="return" or result.value: fail("native SeAssignSecurity failed",result.reason,result.detail,hex(result.value))
        address=m.read_pointer(output)
        if address not in state["allocations"] or not m.read_u16le(address+2)&0x8000: fail("native descriptor ownership/control")
        data=m.read(address,state["allocations"][address][0])
        windows.security_descriptor_parts(data)
        disposed=m.call(base+release_rva,args=[output])
        if disposed.reason!="return" or disposed.value or m.read_pointer(output) or state["allocations"] or state["locks"] or m.read_u16le(thread+0x1e4):
            fail("native key-security resource lifetime")
        m.free(input)
        m.free(output)
        state["cache"][parent]=data
        state["calls"]+=1
        return data
    def create(machine,request):
        if request["api"] not in ["ntcreatekey","regcreatekeyexw"] or request["creator_security"] or request["options"] or request["class_address"]:
            fail("unadmitted native registry creation request",request)
        parent=request["parent_security"]
        if parent==None: fail("native registry creation has no established parent security")
        result={}
        previous=request["parent_key"]
        for key in request["missing_keys"]:
            if (key.rsplit("/",1)[0] or "/") != previous: fail("nonlinear native registry creation request")
            parent=assign(parent)
            result[key]=parent
            previous=key
        return result
    return create
