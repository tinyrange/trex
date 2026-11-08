"""Native effect capture through physical hive deletion and recreation."""

load("//tests:testing.star", "case", "equal", "raises", "suite")

commit = testing.module("@stdlib//windows/servicing:registry_effects.star")
registry_policy = testing.module("@stdlib//windows/selfreg:registry.star")


def _fixture():
    root = directory()
    source = windows.hive_from_patches("SOFTWARE", [
        dict(key="/Recreated", name="Old", type="REG_SZ", value="must not survive"),
        dict(key="/Untouched", name="Keep", type="REG_BINARY", value=b"original"),
        dict(key="/Untouched", name="Drop", type="REG_SZ", value="gone"),
    ], keys=["/Empty"])
    path = "/Windows/System32/config/SOFTWARE"
    root.write(path, source)
    binding = dict(hive="SOFTWARE", prefix="/", target="SOFTWARE", path=path, source=source)
    registry = registry_policy["registry_plugin"](hives={"SOFTWARE":windows.hive(source)})
    return root, binding, registry


def test_capture_commit_does_not_resurrect_deleted_objects():
    root, binding, registry = _fixture()
    registry.set_value("SOFTWARE", "/Recreated", "Abandoned", "REG_DWORD", 1)
    equal(registry.delete_tree("SOFTWARE", "/Recreated"), 0)
    equal(registry.delete_tree("SOFTWARE", "/Empty"), 0)
    registry.set_value("SOFTWARE", "/Recreated/Child", "New", "REG_BINARY", b"actual final")
    registry.set_value("SOFTWARE", "/Untouched", "Keep", "REG_BINARY", b"updated")
    registry.delete_value("SOFTWARE", "/Untouched", "Drop")
    security = windows.compile_sddl("O:SYG:SYD:P(A;;KA;;;SY)")
    registry.set_key_security("SOFTWARE", "/Recreated", security)
    registry.set_key_security("SOFTWARE", "/Recreated/Child", security)
    effects = registry.effects()
    plans = commit["plan_update_registry_effects"](root, effects, [binding])
    # All effects are still only planned at this point.
    equal(windows.hive(root.find(binding["path"])).find("/Empty") != None, True)
    commit["apply_update_registry_effects"](root, plans)
    hive = windows.hive(root.find(binding["path"]))
    equal(hive.find("/Empty"), None)
    equal(hive.find("/Recreated").values, {})
    equal(hive.find("/Recreated").security, security)
    equal(hive.find("/Recreated/Child").values, {"New":b"actual final"})
    equal(hive.find("/Untouched").values, {"Keep":b"updated"})
    equal(hive.find("/Untouched").security, windows.hive(binding["source"]).find("/Untouched").security)


def test_missing_security_and_unbound_mounts_fail_before_writes():
    root, binding, registry = _fixture()
    registry.set_value("SOFTWARE", "/New/Child", "Payload", "REG_DWORD", 4)
    effects = registry.effects()
    before = root.find(binding["path"]).bytes()
    raises(commit["plan_update_registry_effects"], args=[root, effects, [binding]], message="creation security is missing")
    equal(root.find(binding["path"]).bytes(), before)
    # A bare mount detach is NOT deletion of the target hive root.
    effects = dict(keys=[], key_deletions=[dict(hive="SOFTWARE", key="/temporary")], values=[], value_deletions=[])
    mounted = dict(binding)
    mounted["prefix"] = "/temporary"
    raises(commit["plan_update_registry_effects"], args=[root, effects, [mounted]], message="cannot remove a hive root")
    effects["key_deletions"][0]["key"] = "/another-mount/Leaf"
    raises(commit["plan_update_registry_effects"], args=[root, effects, [mounted]], message="no unique explicit hive binding")
    equal(root.find(binding["path"]).bytes(), before)


def test_mount_translation_preserves_literal_parts_and_raw_value_types():
    root, binding, registry = _fixture()
    prefix = "/{native}D:%2fWindows%2fSystem32%2fconfig%2fSOFTWARE"
    mounted = dict(binding)
    mounted["prefix"] = prefix
    descriptor = windows.compile_sddl("O:SYG:SYD:P(A;;KA;;;SY)")
    key = prefix + "/Literal%2fSlash"
    effects = dict(keys=[dict(hive="SOFTWARE", key=key, security=descriptor)], key_deletions=[], values=[dict(hive="SOFTWARE", key=key, name="Opaque", type=0x1234, value=b"\xff\x00\x81")], value_deletions=[])
    plans = commit["plan_update_registry_effects"](root, effects, [mounted])
    commit["apply_update_registry_effects"](root, plans)
    hive = windows.hive(root.find(binding["path"]))
    record = hive.find(["Literal/Slash"]).value_records["Opaque"]
    equal(record.type, 0x1234)
    equal(record.raw, b"\xff\x00\x81")
    equal(hive.find(["Literal/Slash"]).security, descriptor)
    equal(hive.find("/Untouched").values["Keep"], b"original")



def test_literal_owner_leaf_deletions_do_not_remove_display_path_siblings():
    root = directory()
    security = windows.compile_sddl("O:SYG:SYD:P(A;;KA;;;SY)")
    first = ["Drivers", "amd64", "example.inf", "Hash/Leaf="]
    second = ["Drivers", "amd64", "example.inf", "Hash", "Leaf="]
    patches = []
    for parts in [first, second]:
        for name in ["RemovedOwner", "KeptOwner"]:
            patches.append(dict(key_parts=parts, name=name, type="REG_DWORD", value=0))
    path = "/Windows/System32/config/COMPONENTS"
    source = windows.hive_from_patches("COMPONENTS", patches, keys=[dict(key_parts=p, security=security) for p in [first, second]])
    root.write(path, source)
    binding = dict(hive="COMPONENTS", prefix="/", target="COMPONENTS", path=path, source=source)
    registry = registry_policy["registry_plugin"](hives={"COMPONENTS":windows.hive(source)})
    registry.delete_value("COMPONENTS", "/Drivers/amd64/example.inf/Hash%2fLeaf=", "RemovedOwner")
    plans = commit["plan_update_registry_effects"](root, registry.effects(), [binding])
    commit["apply_update_registry_effects"](root, plans)
    hive = windows.hive(root.find(path))
    equal(hive.find(first).values, {"KeptOwner":0})
    equal(hive.find(first).security, security)
    equal(hive.find(second).values, {"RemovedOwner":0, "KeptOwner":0})
    # A subsequent native whole-key deletion still identifies the literal
    # hash leaf, not a split display-path subtree or its owner records.
    binding["source"] = root.find(path)
    registry = registry_policy["registry_plugin"](hives={"COMPONENTS":hive})
    equal(registry.delete_tree("COMPONENTS", "/Drivers/amd64/example.inf/Hash%2fLeaf="), 0)
    plans = commit["plan_update_registry_effects"](root, registry.effects(), [binding])
    commit["apply_update_registry_effects"](root, plans)
    hive = windows.hive(root.find(path))
    equal(hive.find(first), None)
    equal(hive.find(second).values, {"RemovedOwner":0, "KeptOwner":0})


def test_commit_preflights_all_hives_before_first_replacement():
    root, binding, registry = _fixture()
    registry.set_value("SOFTWARE", "/Untouched", "Keep", "REG_BINARY", b"updated")
    plans = commit["plan_update_registry_effects"](root, registry.effects(), [binding])
    second = dict(plans[0])
    second["path"] = "/Windows/System32/config/SYSTEM"
    root.write(second["path"], "concurrent replacement")
    original = root.find(binding["path"]).bytes()
    raises(commit["apply_update_registry_effects"], args=[root, plans + [second]], message="source hive changed before commit")
    equal(root.find(binding["path"]).bytes(), original)


def test_driver_key_creation_matches_independent_kernel_capture():
    native = binary.decode("01000480580000006400000000000000140000000200440003000000000214003f000f0001010000000000051200000000021400000002000101000000000003040000000002140019000200010100000000000100000000010100000000000512000000010100000000000512000000", "hex")
    parent = windows.compile_sddl("O:BAG:BUD:(A;CI;KA;;;SY)(A;CI;RC;;;OW)(A;CI;KR;;;WD)")
    equal(commit["build_update_driver_key_security"](parent),native)
    equal(commit["build_update_driver_key_security"](native),native)
    for invalid in ["O:BAG:BUD:AI(A;CI;KA;;;SY)(A;CI;RC;;;OW)(A;CI;KR;;;WD)","O:BAG:BUD:(A;CI;KA;;;SY)"]:
        raises(commit["build_update_driver_key_security"],args=[windows.compile_sddl(invalid)],message="unestablished native driver key creation parent policy")
    raises(commit["update_driver_key_creation_provider"],args=[{},"S-1-5-19","S-1-5-18",0x3000],message="established SYSTEM subject")


def test_components_owner_creation_matches_independent_kernel_capture():
    # Target ntkrnlmp C29EBFB06B78B3C020DCA66D99713F9E, DBI age1;
    # CmpCreateChild -> SeAssignSecurity with actual COMPONENTS parent bytes,
    # NULL creator, explicit SYSTEM subject, registry mapping, container=1.
    # Native 4170 instructions, actual owned output, lock/APC counts back to 0.
    captured = binary.decode("01000480d8000000e400000000000000140000000200c40007000000000218001900020001020000000000052000000021020000000218003f000f0001020000000000052000000020020000000214003f000f00010100000000000512000000000014003f000f00010100000000000512000000000a14003f000f000101000000000003000000000002180019000200010200000000000f02000000010000000002380019000200010a00000000000f0300000000040000b031803f6cbc634c3ce050d1970ca1620f01cb197e7aa6c0fae697f119a30cce010100000000000512000000010100000000000512000000", "hex")
    # Independently executed SeAssignSecurity against the actual SOFTWARE
    # Print/PackagesToAdd parent: 4170 instructions, same 240-byte child.
    print_parent=binary.decode("01000480dc000000ec00000000000000140000000200c80007000000000218001900020001020000000000052000000021020000000218003f000f0001020000000000052000000020020000000214003f000f00010100000000000512000000000018003f000f0001020000000000052000000020020000000a14003f000f000101000000000003000000000002180019000200010200000000000f02000000010000000002380019000200010a00000000000f0300000000040000b031803f6cbc634c3ce050d1970ca1620f01cb197e7aa6c0fae697f119a30cce010200000000000520000000200200000105000000000005150000009a58dcef44cb6506d87e569e01020000", "hex")
    equal(commit["build_update_driver_key_security"](print_parent),captured)
    changed_print=binary.builder().append(print_parent)
    changed_print.patch_u32le(32,0x20018)
    raises(commit["build_update_driver_key_security"],args=[changed_print.bytes()],message="unestablished native")
    equal(len(captured),240)
    equal(commit["build_update_driver_key_security"](captured),captured)
    parts=windows.security_descriptor_parts(captured)
    # The token supplies owner/group; copying parent principals is wrong.
    principals=windows.security_descriptor_parts(windows.compile_sddl("O:BAG:BU"))
    parent=binary.builder().append(captured).append(principals["owner"]).append(principals["group"])
    parent.patch_u32le(4,len(captured))
    parent.patch_u32le(8,len(captured)+len(principals["owner"]))
    equal(commit["build_update_driver_key_security"](parent.bytes()),captured)
    changed=binary.builder().append(captured)
    changed.patch_u32le(32,0x20018)
    raises(commit["build_update_driver_key_security"],args=[changed.bytes()],message="unestablished native")


def test_native_owner_creation_requires_exact_descriptor_and_owned_privileges():
    registry_module=testing.module("@stdlib//windows/selfreg:registry.star")
    win32=testing.module("@stdlib//windows/selfreg:win32.star")
    captured=binary.decode("01000480d8000000e400000000000000140000000200c40007000000000218001900020001020000000000052000000021020000000218003f000f0001020000000000052000000020020000000214003f000f00010100000000000512000000000014003f000f00010100000000000512000000000a14003f000f000101000000000003000000000002180019000200010200000000000f02000000010000000002380019000200010a00000000000f0300000000040000b031803f6cbc634c3ce050d1970ca1620f01cb197e7aa6c0fae697f119a30cce010100000000000512000000010100000000000512000000","hex")
    for architecture in ["x86","amd64"]:
        for mode in ["owned","disabled","missing","no-thread","foreign-creator","wrong-options"]:
            kernel=win32["kernel32_plugin"]()
            privileges={17:2,18:2}
            if mode=="disabled": privileges[18]=0
            if mode=="missing": privileges.pop(18)
            security=win32["security_plugin"](user_name="SYSTEM",user_sid=[18],kernel=kernel,token_privileges=privileges)
            ref={}
            create=commit["update_driver_key_creation_provider"](ref,"S-1-5-18","S-1-5-18",0x4000)
            registry=registry_module["registry_plugin"](keys=[dict(hive="SOFTWARE",key="/Parent")],on_create_key=create)
            ref["registry"]=registry
            registry.set_key_security("SOFTWARE","/Parent",captured)
            before=registry.effects()
            machine=emulator.machine(code=b"\xc3",architecture=architecture)
            machine.use([kernel,security,registry])
            if mode!="no-thread":
                equal(machine.call(machine.resolve_export("advapi32.dll",name="ImpersonateSelf"),args=[2]).value,1)
            creator=windows.compile_sddl("O:BAG:SY" if mode=="foreign-creator" else "O:SYG:SY")
            sa=machine.allocate(size=24 if machine.pointer_size==8 else 12)
            machine.write_u32le(sa,24 if machine.pointer_size==8 else 12)
            machine.write_pointer(sa+(8 if machine.pointer_size==8 else 4),machine.allocate(value=creator))
            subkey=machine.allocate(value=binary.encode("Parent"+chr(92)+"New",encoding="utf16le",nul=True))
            output=machine.allocate(size=machine.pointer_size+4)
            result=machine.call(machine.resolve_export("advapi32.dll",name="RegCreateKeyExW"),args=[0x80000002,subkey,0,0,0 if mode=="wrong-options" else 4,0x2001f,sa,output,output+machine.pointer_size])
            if mode=="owned":
                equal(result.reason,"return",result.detail)
                equal(result.value,0)
                equal(registry.effects()["keys"][-1]["security"],captured)
            else:
                equal(result.reason,"plugin")
                equal("native owner" in result.detail,True,result.detail)
                equal(registry.effects(),before)
            # The provider must not invent or enable a missing/disabled LUID.
            equal(security.state["process_token"]["privileges"],privileges)


def test_driver_unmount_persists_before_namespace_teardown_and_remount():
    root, binding, registry = _fixture()
    mounts = testing.module("@stdlib//windows/servicing:driver_hives.star")
    win32 = testing.module("@stdlib//windows/selfreg:win32.star")
    physical = ("D:"+binding["path"]).replace("/",chr(92))
    kernel = win32["kernel32_plugin"](files={physical:root.find(binding["path"])})
    mount = mounts["update_driver_hive_mounts"](registry,root,{physical.lower():dict(target="SOFTWARE",path=binding["path"])})
    mount.state["kernel"] = kernel
    registry.state["sources"]["SOFTWARE"] = mount
    machine = emulator.machine(code=b"\xc3",architecture="amd64")
    machine.use(kernel)
    machine.use(registry)
    machine.use(mount)
    name = machine.allocate(value=binary.encode("MountFixture",encoding="utf16le",nul=True))
    file = machine.allocate(value=binary.encode(physical,encoding="utf16le",nul=True))
    load_hive = machine.resolve_export("api-ms-win-core-registry-l1-1-0.dll",name="RegLoadKeyW")
    unload_hive = machine.resolve_export("api-ms-win-core-registry-l1-1-0.dll",name="RegUnLoadKeyW")
    open_key = machine.resolve_export("advapi32.dll",name="RegOpenKeyExW")
    close = machine.resolve_export("advapi32.dll",name="RegCloseKey")
    for iteration in range(2):
        equal(machine.call(load_hive,args=[0x80000002,name,file]).value,0)
        output = machine.allocate(size=8)
        equal(machine.call(open_key,args=[0x80000002,name,0,0x20019,output]).value,0)
        handle = machine.read_pointer(output)
        value = "First" if iteration==0 else "Second"
        registry.set_value("SOFTWARE","/MountFixture/Untouched",value,"REG_DWORD",iteration+11)
        before = root.find(binding["path"]).bytes()
        busy = machine.call(unload_hive,args=[0x80000002,name])
        equal(busy.reason,"return",busy.detail)
        equal(busy.value,5)
        equal(root.find(binding["path"]).bytes(),before)
        equal(machine.call(close,args=[handle]).value,0)
        result = machine.call(unload_hive,args=[0x80000002,name])
        equal(result.reason,"return",result.detail)
        equal(result.value,0)
        equal(mount.state["mounts"],{})
        written = windows.hive(root.find(binding["path"]))
        equal(written.find("/Untouched").values["First"],11)
        if iteration:
            equal(written.find("/Untouched").values["Second"],12)
        equal(written.find("/Untouched").values["Keep"],b"original")
        equal(written.find("/Empty")!=None,True)
    equal(len(mount.state["commits"]),2)


def test_native_hive_flush_persists_with_open_references():
    root,binding,registry=_fixture()
    mounts=testing.module("@stdlib//windows/servicing:driver_hives.star")
    win32=testing.module("@stdlib//windows/selfreg:win32.star")
    physical=("D:"+binding["path"]).replace("/",chr(92))
    kernel=win32["kernel32_plugin"](files={physical:root.find(binding["path"])})
    mount=mounts["update_driver_hive_mounts"](registry,root,{physical.lower():dict(target="SOFTWARE",path=binding["path"])})
    mount.state["kernel"]=kernel
    registry.state["sources"]["SOFTWARE"]=mount
    machine=emulator.machine(code=b"\xc3",architecture="amd64")
    machine.use([kernel,registry,mount])
    name=machine.allocate(value=binary.encode("FlushFixture",encoding="utf16le",nul=True))
    file=machine.allocate(value=binary.encode(physical,encoding="utf16le",nul=True))
    load_hive=machine.resolve_export("api-ms-win-core-registry-l1-1-0.dll",name="RegLoadKeyW")
    unload=machine.resolve_export("api-ms-win-core-registry-l1-1-0.dll",name="RegUnLoadKeyW")
    opened=machine.resolve_export("advapi32.dll",name="RegOpenKeyExW")
    flush=machine.resolve_export("ntdll.dll",name="NtFlushKey")
    equal(machine.call(load_hive,args=[0x80000002,name,file]).value,0)
    output=machine.allocate(size=8)
    equal(machine.call(opened,args=[0x80000002,name,0,0x20019,output]).value,0)
    handle=machine.read_pointer(output)
    for iteration in range(2):
        registry.set_value("SOFTWARE","/FlushFixture/Untouched","Payload","REG_DWORD",iteration+11)
        before=root.find(binding["path"]).bytes()
        equal(machine.call(flush,args=[123]).value,0xc0000008)
        equal(root.find(binding["path"]).bytes(),before)
        equal(machine.call(flush,args=[handle]).value,0)
        hive=windows.hive(root.find(binding["path"]))
        equal(hive.find("/Untouched").values["Payload"],iteration+11)
        equal(hive.find("/Untouched").values["Keep"],b"original")
        equal(len(mount.state["mounts"]),1)
        equal(registry.state["handles"][handle]!=None,True)
        # Flush persists bytes but must not detach or waive busy references.
        before=root.find(binding["path"]).bytes()
        equal(machine.call(unload,args=[0x80000002,name]).value,5)
        equal(root.find(binding["path"]).bytes(),before)
    equal(machine.call(machine.resolve_export("advapi32.dll",name="RegCloseKey"),args=[handle]).value,0)
    equal(machine.call(unload,args=[0x80000002,name]).value,0)
    equal(mount.state["mounts"],{})
    equal(len(mount.state["flushes"]),2)
    # Unload has no new delta after the two successful native flushes.
    equal(len(mount.state["commits"]),2)
    equal(windows.hive(root.find(binding["path"])).find("/Untouched").values["Payload"],12)


def test_native_synchronous_unload_never_discards_live_references():
    root,binding,registry=_fixture()
    mounts=testing.module("@stdlib//windows/servicing:driver_hives.star")
    win32=testing.module("@stdlib//windows/selfreg:win32.star")
    physical=("D:"+binding["path"]).replace("/",chr(92))
    kernel=win32["kernel32_plugin"](files={physical:root.find(binding["path"])})
    mount=mounts["update_driver_hive_mounts"](registry,root,{physical.lower():dict(target="SOFTWARE",path=binding["path"])})
    mount.state["kernel"]=kernel
    registry.state["sources"]["SOFTWARE"]=mount
    machine=emulator.machine(code=b"\xc3",architecture="amd64")
    machine.use([kernel,registry,mount])
    name=machine.allocate(value=binary.encode("SyncFixture",encoding="utf16le",nul=True))
    file=machine.allocate(value=binary.encode(physical,encoding="utf16le",nul=True))
    load_hive=machine.resolve_export("api-ms-win-core-registry-l1-1-0.dll",name="RegLoadKeyW")
    equal(machine.call(load_hive,args=[0x80000002,name,file]).value,0)
    output=machine.allocate(size=8)
    equal(machine.call(machine.resolve_export("advapi32.dll",name="RegOpenKeyExW"),args=[0x80000002,name,0,0x20019,output]).value,0)
    handle=machine.read_pointer(output)
    registry.set_value("SOFTWARE","/SyncFixture/Untouched","Payload","REG_DWORD",71)
    value=binary.encode(chr(92)+"Registry"+chr(92)+"Machine"+chr(92)+"SyncFixture",encoding="utf16le")
    text=machine.allocate(value=value)
    descriptor=machine.allocate(size=16)
    machine.write_u16le(descriptor,len(value))
    machine.write_u16le(descriptor+2,len(value))
    machine.write_pointer(descriptor+8,text)
    attributes=machine.allocate(size=48)
    machine.write_u32le(attributes,48)
    machine.write_pointer(attributes+16,descriptor)
    machine.write_u32le(attributes+24,0x40)
    unload=machine.resolve_export("ntdll.dll",name="NtUnloadKey2")
    before=root.find(binding["path"]).bytes()
    classic_unload=machine.resolve_export("api-ms-win-core-registry-l1-1-0.dll",name="RegUnLoadKeyW")
    equal(machine.call(classic_unload,args=[0x80000002,name]).value,5)
    busy=machine.call(unload,args=[attributes,1])
    equal(busy.reason,"plugin")
    equal("live references is not modeled" in busy.detail,True)
    equal(root.find(binding["path"]).bytes(),before)
    equal(len(mount.state["mounts"]),1)
    equal(registry.state["handles"][handle]!=None,True)
    equal(machine.call(machine.resolve_export("advapi32.dll",name="RegCloseKey"),args=[handle]).value,0)
    result=machine.call(unload,args=[attributes,1])
    equal(result.reason,"return",result.detail)
    equal(result.value,0)
    equal(mount.state["mounts"],{})
    equal(mount.state["pending"],{})
    equal(len(mount.state["commits"]),1)
    equal(mount.state.get("busy_unload",{}),{})
    equal(windows.hive(root.find(binding["path"])).find("/Untouched").values["Payload"],71)


def test_mounted_object_name_uses_native_namespace_and_bounded_buffers():
    mounts=testing.module("@stdlib//windows/servicing:driver_hives.star")
    for arch in ["x86","amd64"]:
        root,binding,registry=_fixture()
        # Percent escapes must be decoded only once and after path splitting.
        mount_name="{native}D:/Windows/System32/config/SYSTEM%2f"
        leaf="Literal/Slash%2f"+chr(0x1f600)
        physical=("D:"+binding["path"]).replace("/",chr(92))
        provider=mounts["update_driver_hive_mounts"](registry,root,{physical.lower():dict(target="SOFTWARE",path=binding["path"])})
        registry.state["sources"]["SOFTWARE"]=provider
        machine=emulator.machine(code=b"\xc3",architecture=arch)
        machine.use([registry,provider])
        name=machine.allocate(value=binary.encode(mount_name,encoding="utf16le",nul=True))
        file=machine.allocate(value=binary.encode(physical,encoding="utf16le",nul=True))
        equal(machine.call(machine.resolve_export("api-ms-win-core-registry-l1-1-0.dll",name="RegLoadKeyW"),args=[0x80000002,name,file]).value,0)
        registry.load_keys([dict(hive="SOFTWARE",key_parts=[mount_name,leaf])])
        path=machine.allocate(value=binary.encode(mount_name+chr(92)+leaf,encoding="utf16le",nul=True))
        handle_out=machine.allocate(size=8)
        equal(machine.call(machine.resolve_export("advapi32.dll",name="RegOpenKeyExW"),args=[0x80000002,path,0,0x20019,handle_out]).value,0)
        handle=machine.read_pointer(handle_out)
        query=machine.resolve_export("ntdll.dll",name="NtQueryObject")
        text=binary.encode(chr(92)+"REGISTRY"+chr(92)+"MACHINE"+chr(92)+mount_name+chr(92)+leaf,encoding="utf16le")
        header=16 if arch=="amd64" else 8
        required=header+len(text)+2
        storage=machine.allocate(value=b"Q"*(required+16))
        output=storage+8
        length=machine.allocate(value=b"L"*12)
        needed=length+4
        for capacity,out in [(0,0),(0,output),(header-1,output),(required-1,output)]:
            result=machine.call(query,args=[handle,1,out,capacity,needed])
            equal(result.reason,"return",result.detail)
            equal(result.value,0xc0000004)
            equal(machine.read_u32le(needed),required)
            equal(machine.read(storage,required+16),b"Q"*(required+16))
            equal(machine.read(length,4),b"LLLL")
            equal(machine.read(length+8,4),b"LLLL")
        result=machine.call(query,args=[handle,1,output,required,needed])
        equal(result.reason,"return",result.detail)
        equal(result.value,0)
        equal(machine.read_u16le(output),len(text))
        equal(machine.read_u16le(output+2),len(text)+2)
        equal(machine.read_pointer(output+(8 if arch=="amd64" else 4)),output+header)
        if arch=="amd64": equal(machine.read(output+4,4),b"\x00"*4)
        equal(machine.read(output+header,len(text)),text)
        equal(machine.read_u16le(output+header+len(text)),0)
        equal(machine.read(storage,8),b"Q"*8)
        equal(machine.read(output+required,8),b"Q"*8)
        # Never reinterpret arbitrary registry/kernel handles or other classes.
        for args,message in [([handle,0,output,required,needed],"information class"),([0x80000002,1,output,required,needed],"unique owned hive mount"),([handle,1,output,required,0],"ReturnLength"),([handle,1,0,required,needed],"NULL output")]:
            result=machine.call(query,args=args)
            equal(result.reason,"plugin",result.detail)
            equal(message in result.detail,True,result.detail)
        equal(machine.call(query,args=[123,1,output,required,needed]).value,0xc0000008)
        equal(machine.call(machine.resolve_export("advapi32.dll",name="RegCloseKey"),args=[handle]).value,0)
        equal(machine.call(query,args=[handle,1,output,required,needed]).value,0xc0000008)


def test_wudf_key_creation_matches_actual_kernel_fixed_point():
    captured=binary.decode("0100048cbc010000c801000000000000140000000200a8010e000000001314003f000f0001010000000000051200000000131400190002000101000000000005130000000013140019000200010100000000000514000000001318003f000f0001020000000000052000000020020000001318001900020001020000000000052000000021020000001028003f000f00010600000000000550000000b589fb381984c2cb5c6c236d5700776ec0026487001a280000000010010600000000000550000000b589fb381984c2cb5c6c236d5700776ec0026487001a140000000010010100000000000512000000001a18000000001001020000000000052000000020020000001a180000000080010200000000000520000000210200000010180019000200010200000000000f0200000001000000001a180000000080010200000000000f02000000010000000010380019000200010a00000000000f0300000000040000b031803f6cbc634c3ce050d1970ca1620f01cb197e7aa6c0fae697f119a30cce001a380000000080010a00000000000f0300000000040000b031803f6cbc634c3ce050d1970ca1620f01cb197e7aa6c0fae697f119a30cce010100000000000512000000010100000000000512000000","hex")
    parent=binary.builder(capacity=len(captured))
    parent.append(captured)
    parent.patch_u16le(2,0x8c14)
    equal(commit["build_update_driver_key_security"](parent.bytes()),captured)
    equal(commit["build_update_driver_key_security"](captured),captured)
    equal(len(windows.acl_entries(windows.security_descriptor_parts(captured)["dacl"])["entries"]),14)
    changed=binary.builder(capacity=len(captured))
    changed.append(captured)
    changed.patch_u32le(32,0x20019)
    raises(commit["build_update_driver_key_security"],args=[changed.bytes()],message="unestablished native")


def test_native_open_reference_report_resizes_without_fabricating_entries():
    mounts=testing.module("@stdlib//windows/servicing:driver_hives.star")
    win32=testing.module("@stdlib//windows/selfreg:win32.star")
    root,binding,registry=_fixture()
    root.write(binding["path"],windows.hive_from_patches("SOFTWARE",[dict(key="/Child"+str(i),name="Value",type="REG_DWORD",value=i) for i in range(30)]))
    physical=("D:"+binding["path"]).replace("/",chr(92))
    provider=mounts["update_driver_hive_mounts"](registry,root,{physical.lower():dict(target="SOFTWARE",path=binding["path"])})
    registry.state["sources"]["SOFTWARE"]=provider
    machine=emulator.machine(code=b"\xc3",architecture="amd64")
    machine.use([win32["kernel32_plugin"](),registry,provider])
    mount="ReportMount"
    name=machine.allocate(value=binary.encode(mount,encoding="utf16le",nul=True))
    path=machine.allocate(value=binary.encode(physical,encoding="utf16le",nul=True))
    equal(machine.call(machine.resolve_export("kernelbase.dll",name="RegLoadKeyW"),args=[0x80000002,name,path]).value,0)
    handles=[]
    opened=machine.allocate(size=8)
    for i in range(30):
        key=machine.allocate(value=binary.encode(mount+chr(92)+"Child"+str(i),encoding="utf16le",nul=True))
        equal(machine.call(machine.resolve_export("kernelbase.dll",name="RegOpenKeyExW"),args=[0x80000002,key,0,0x20019,opened]).value,0)
        handles.append(machine.read_pointer(opened))
    native=chr(92)+"REGISTRY"+chr(92)+"MACHINE"+chr(92)+mount
    names=[binary.encode(native+chr(92)+"Child"+str(i),encoding="utf16le") for i in range(30)]
    required=8+24*30
    for text in names: required+=len(text)+2
    text=machine.allocate(value=binary.encode(native,encoding="utf16le",nul=True))
    desc=machine.allocate(size=16)
    machine.write_u16le(desc,len(binary.encode(native,encoding="utf16le")))
    machine.write_u16le(desc+2,len(binary.encode(native,encoding="utf16le"))+2)
    machine.write_pointer(desc+8,text)
    oa=machine.allocate(size=48)
    machine.write_u32le(oa,48)
    machine.write_pointer(oa+16,desc)
    storage=machine.allocate(size=required+16)
    output=storage+8
    length=machine.allocate(value=b"L"*12)
    needed=length+4
    query=machine.resolve_export("ntdll.dll",name="NtQueryOpenSubKeysEx")
    for capacity in [0,4,8,1024,required-1]:
        machine.write(storage,b"G"*(required+16))
        result=machine.call(query,args=[oa,0x600000000000|capacity,output,needed])
        equal((result.reason,result.value),("return",0x80000005))
        equal(machine.read_u32le(needed),required)
        equal(machine.read(storage,required+16),b"G"*(required+16))
        equal(machine.read(length,4),b"LLLL")
        equal(machine.read(length+8,4),b"LLLL")
        equal(provider.state.get("reports",[]),[])
    result=machine.call(query,args=[oa,required,output,needed])
    equal((result.reason,result.value),("return",0))
    equal(machine.read_u32le(output),30)
    equal(machine.read_u32le(needed),required)
    for index,text in enumerate(names):
        entry=output+8+24*index
        equal(machine.read_pointer(entry),4)
        equal(machine.read_u16le(entry+8),len(text))
        equal(machine.read_u16le(entry+10),len(text)+2)
        address=machine.read_pointer(entry+16)
        equal(address>=output+8+24*30 and address+len(text)+2<=output+required,True)
        equal(machine.read(address,len(text)),text)
        equal(machine.read_u16le(address+len(text)),0)
    equal(machine.read(storage,8),b"G"*8)
    equal(machine.read(output+required,8),b"G"*8)
    equal(provider.state["reports"][-1]["handles"],handles)
    close=machine.resolve_export("advapi32.dll",name="RegCloseKey")
    for handle in handles: equal(machine.call(close,args=[handle]).value,0)
    equal(machine.call(query,args=[oa,8,output,needed]).value,0)
    equal(machine.read_u32le(output),0)
    equal(machine.read_u32le(needed),8)


def test_driver_hive_mount_host_alias_retains_epoch_identity():
    mounts=testing.module("@stdlib//windows/servicing:driver_hives.star")
    for arch in ["x86","amd64"]:
        root,binding,registry=_fixture()
        physical=("D:"+binding["path"]).replace("/",chr(92))
        provider=mounts["update_driver_hive_mounts"](registry,root,{physical.lower():dict(target="SOFTWARE",path=binding["path"])})
        registry.state["sources"]["SOFTWARE"]=provider
        machine=emulator.machine(code=b"\xc3",architecture=arch)
        machine.use([registry,provider])
        source=machine.allocate(value=binary.encode(physical,encoding="utf16le",nul=True))
        for host in ["kernelbase.dll","api-ms-win-core-registry-l1-1-0.dll"]:
            name=machine.allocate(value=binary.encode("HostEpoch",encoding="utf16le",nul=True))
            loaded=machine.call(machine.resolve_export(host,name="RegLoadKeyW"),args=[0x80000002,name,source])
            equal(loaded.reason,"return",loaded.detail)
            equal(loaded.value,0)
            equal(len(provider.state["mounts"]),1)
            unloaded=machine.call(machine.resolve_export(host,name="RegUnLoadKeyW"),args=[0x80000002,name])
            equal(unloaded.reason,"return",unloaded.detail)
            equal(unloaded.value,0)
            equal(provider.state["mounts"],{})
            equal(provider.state["pending"],{})
        equal(len(provider.state["loads"]),2)


def test_device_property_creation_matches_native_protected_then_inherited_security():
    win32 = testing.module("@stdlib//windows/selfreg:win32.star")
    abi = testing.module("@stdlib//windows/emulation:abi.star")
    native = binary.decode("01000480580000006400000000000000140000000200440003000000000214003f000f0001010000000000051200000000021400000002000101000000000003040000000002140019000200010100000000000100000000010100000000000512000000010100000000000512000000", "hex")
    creator = commit["_DRIVER_PROPERTY_CREATOR"]
    protected = commit["_DRIVER_PROPERTY_PROTECTED"]
    inherited = commit["_DRIVER_PROPERTY_INHERITED"]
    equal(commit["build_update_driver_property_key_security"](native, creator), protected)
    equal(commit["build_update_driver_key_security"](protected), inherited)
    equal(commit["build_update_driver_key_security"](inherited), inherited)
    changed = binary.builder().append(creator)
    changed.patch_u32le(32, 0x20019)
    raises(commit["build_update_driver_property_key_security"], args=[native, changed.bytes()], message="creator descriptor")
    raises(commit["build_update_driver_property_key_security"], args=[protected, creator], message="creation parent")
    for architecture in ["x86", "amd64"]:
        for valid in [True, False]:
            ref = {}
            create = commit["update_driver_key_creation_provider"](ref, "S-1-5-18", "S-1-5-18", 0x3000)
            registry = registry_policy["registry_plugin"](keys=[dict(hive="SOFTWARE", key="/Parent")], on_create_key=create)
            ref["registry"] = registry
            registry.set_key_security("SOFTWARE", "/Parent", native)
            m = emulator.machine(architecture=architecture, code=b"\xc3")
            m.use([win32["kernel32_plugin"](), registry])
            before = registry.effects()
            layout = abi["object_attributes_layout"](m.pointer_size)
            fields = layout
            oa = m.allocate(size=layout["Size"])
            m.write_u32le(oa, layout["Size"])
            m.write_pointer(oa+fields["RootDirectory"], 0x80000002)
            unicode = abi["counted_string_layout"](m.pointer_size)
            name = m.allocate(size=unicode["Size"])
            path = binary.encode("Parent"+chr(92)+"Properties", encoding="utf16le")
            m.write_u16le(name, len(path))
            m.write_u16le(name+2, len(path))
            m.write_pointer(name+unicode["Buffer"], m.allocate(value=path))
            m.write_pointer(oa+fields["ObjectName"], name)
            m.write_pointer(oa+fields["SecurityDescriptor"], m.allocate(value=creator if valid else changed.bytes()))
            output = m.allocate(value=b"G"*16)
            disposition = m.allocate(value=b"D"*8)
            result = m.call(m.resolve_export("ntdll.dll",name="NtCreateKey"),args=[output,4,oa,0,0,0,disposition])
            if valid:
                equal(result.reason, "return", result.detail)
                equal(result.value, 0)
                equal(registry.effects()["keys"][-1]["security"], protected)
                equal(m.read(output+m.pointer_size, 16-m.pointer_size), b"G"*(16-m.pointer_size))
                equal(m.read(disposition, 8), binary.encode(chr(1)+chr(0)*3+"D"*4, encoding="ascii"))
            else:
                equal(result.reason, "plugin")
                equal(registry.effects(), before)
                equal(m.read(output,16),b"G"*16)
                equal(m.read(disposition,8),b"D"*8)


def test_winevt_publisher_creation_matches_actual_kernel_fixed_point():
    child = binary.decode("0100048c58010000640100000000000014000000020044010b000000001018001900020001020000000000052000000021020000001a18000000008001020000000000052000000021020000001018003f000f0001020000000000052000000020020000001a18000000001001020000000000052000000020020000001014003f000f00010100000000000512000000001a140000000010010100000000000512000000001a1400000000100101000000000003000000000010180019000200010200000000000f0200000001000000001a180000000080010200000000000f02000000010000000010380019000200010a00000000000f0300000000040000b031803f6cbc634c3ce050d1970ca1620f01cb197e7aa6c0fae697f119a30cce001a380000000080010a00000000000f0300000000040000b031803f6cbc634c3ce050d1970ca1620f01cb197e7aa6c0fae697f119a30cce010100000000000512000000010100000000000512000000", "hex")
    parent = binary.builder().append(child)
    parent.patch_u16le(2, 0x8c14)
    equal(commit["build_update_driver_key_security"](parent.bytes()), child)
    equal(commit["build_update_driver_key_security"](child), child)
    changed = binary.builder().append(parent.bytes())
    changed.patch_u32le(32, 0x20018)
    raises(commit["build_update_driver_key_security"], args=[changed.bytes()], message="unestablished native")


def test_eventlog_creation_matches_actual_kernel_fixed_point():
    child = binary.decode("0100048ccc000000d800000000000000140000000200b80008000000001014001900020001010000000000050b000000001a14000000008001010000000000050b000000001018001900020001020000000000052000000025020000001a18000000008001020000000000052000000025020000001018003f000f0001020000000000052000000020020000001a18000000001001020000000000052000000020020000001014003f000f00010100000000000512000000001a140000000010010100000000000512000000010100000000000512000000010100000000000512000000", "hex")
    parent = binary.builder().append(child)
    parent.patch_u16le(2, 0x8c14)
    equal(commit["build_update_driver_key_security"](parent.bytes()), child)
    equal(commit["build_update_driver_key_security"](child), child)
    changed = binary.builder().append(parent.bytes())
    changed.patch_u32le(32, 0x20018)
    raises(commit["build_update_driver_key_security"], args=[changed.bytes()], message="unestablished native")


def test_wmi_autologger_creation_preserves_measured_audit_inheritance():
    parent = commit["_DRIVER_WMI_AUTOLOGGER_PARENT"]
    child = commit["_DRIVER_WMI_AUTOLOGGER_CHILD"]
    equal(commit["build_update_driver_key_security"](parent), child)
    equal(commit["build_update_driver_key_security"](child), child)
    equal(windows.security_descriptor_parts(child)["control"], 0x8c14)
    equal(windows.security_descriptor_parts(child)["sacl"] != None, True)
    equal(parent == child, False)
    for offset,value in [(32,0xd0007),(60,0x20018)]:
        changed = binary.builder().append(parent)
        changed.patch_u32le(offset,value)
        raises(commit["build_update_driver_key_security"], args=[changed.bytes()], message="unestablished native")


def test_native_flush_deltas_do_not_replay_commits_or_lose_empty_recreation():
    root,binding,registry = _fixture()
    mounts = testing.module("@stdlib//windows/servicing:driver_hives.star")
    win32 = testing.module("@stdlib//windows/selfreg:win32.star")
    physical = ("D:"+binding["path"]).replace("/",chr(92))
    kernel = win32["kernel32_plugin"](files={physical:root.find(binding["path"])})
    mount = mounts["update_driver_hive_mounts"](registry,root,{physical.lower():dict(target="SOFTWARE",path=binding["path"])})
    mount.state["kernel"] = kernel
    registry.state["sources"]["SOFTWARE"] = mount
    machine = emulator.machine(code=b"\xc3",architecture="amd64")
    machine.use([kernel,registry,mount])
    name = machine.allocate(value=binary.encode("DeltaFlush",encoding="utf16le",nul=True))
    file = machine.allocate(value=binary.encode(physical,encoding="utf16le",nul=True))
    equal(machine.call(machine.resolve_export("kernelbase.dll",name="RegLoadKeyW"),args=[0x80000002,name,file]).value,0)
    out = machine.allocate(size=8)
    equal(machine.call(machine.resolve_export("advapi32.dll",name="RegOpenKeyExW"),args=[0x80000002,name,0,0x20019,out]).value,0)
    handle = machine.read_pointer(out)
    flush = machine.resolve_export("ntdll.dll",name="NtFlushKey")
    key = "/DeltaFlush/Recreated"
    descriptor = windows.compile_sddl("O:SYG:SYD:P(A;;KA;;;SY)")
    registry.set_value("SOFTWARE",key,"First","REG_DWORD",11)
    registry.set_key_security("SOFTWARE",key,descriptor)
    equal(machine.call(flush,args=[handle]).value,0)
    equal(windows.hive(root.find(binding["path"])).find("/Recreated").values["First"],11)
    before = root.find(binding["path"]).bytes()
    for unused in range(8):
        equal(machine.call(flush,args=[handle]).value,0)
    equal(root.find(binding["path"]).bytes(),before)
    equal(len(mount.state["commits"]),1)
    equal(registry.delete_tree("SOFTWARE",key),0)
    # Same final key descriptor, different incarnation, no surviving values.
    registry.set_key_security("SOFTWARE",key,descriptor)
    equal(machine.call(flush,args=[handle]).value,0)
    recreated = windows.hive(root.find(binding["path"])).find("/Recreated")
    equal(recreated.values,{})
    equal(recreated.security,descriptor)
    equal(len(mount.state["commits"]),2)
    changed = windows.compile_sddl("O:SYG:SYD:P(A;;KR;;;SY)")
    registry.set_key_security("SOFTWARE",key,changed)
    equal(machine.call(flush,args=[handle]).value,0)
    after = windows.hive(root.find(binding["path"]))
    equal(after.find("/Recreated").security,changed)
    equal(after.find("/Recreated").values,{})
    equal(after.find("/Untouched").values["Keep"],b"original")
    equal(len(mount.state["commits"]),3)
    equal(machine.call(machine.resolve_export("advapi32.dll",name="RegCloseKey"),args=[handle]).value,0)
    equal(machine.call(machine.resolve_export("kernelbase.dll",name="RegUnLoadKeyW"),args=[0x80000002,name]).value,0)
    equal(mount.state["mounts"],{})
    equal(mount.state["epochs"],{})
    equal(len(mount.state["commits"]),3)




def test_completed_driver_host_retirement_persists_real_handles_and_rejects_early_close():
    root, binding, registry = _fixture()
    mounts = testing.module("@stdlib//windows/servicing:driver_hives.star")
    cleanup = testing.module("@stdlib//windows/servicing:driver_cleanup.star")
    win32 = testing.module("@stdlib//windows/selfreg:win32.star")
    physical = ("D:"+binding["path"]).replace("/",chr(92))
    kernel = win32["kernel32_plugin"](files={physical:root.find(binding["path"])})
    mount = mounts["update_driver_hive_mounts"](registry,root,{physical.lower():dict(target="SOFTWARE",path=binding["path"])})
    mount.state["kernel"] = kernel
    registry.state["sources"]["SOFTWARE"] = mount
    machine = emulator.machine(code=b"\xc3",architecture="amd64")
    machine.use([kernel,registry,mount])
    name = machine.allocate(value=binary.encode("RetiredHost",encoding="utf16le",nul=True))
    file = machine.allocate(value=binary.encode(physical,encoding="utf16le",nul=True))
    equal(machine.call(machine.resolve_export("kernelbase.dll",name="RegLoadKeyW"),args=[0x80000002,name,file]).value,0)
    output = machine.allocate(size=8)
    equal(machine.call(machine.resolve_export("advapi32.dll",name="RegOpenKeyExW"),args=[0x80000002,name,0,0x20019,output]).value,0)
    handle = machine.read_pointer(output)
    registry.set_value("SOFTWARE","/RetiredHost/Untouched","Completed","REG_DWORD",42)
    session = dict(machine=machine,registry=registry,mount=mount,completed=['open','stage'],process_detached=['drupdate.dll','drvstore.dll'])
    before = root.find(binding['path']).bytes()
    raises(cleanup['retire_update_driver_process'],args=[session],message='requires all native phases')
    equal(root.find(binding['path']).bytes(),before)
    equal(registry.state['handles'][handle]!=None,True)
    session['completed'] = ['open','stage','install','uninstall','close']
    result = cleanup['retire_update_driver_process'](session)
    equal(result['registry_references'],1)
    equal(result['hives'],1)
    equal(mount.state['epochs'],{})
    equal(registry.state['handles'].get(handle),None)
    after = windows.hive(root.find(binding['path']))
    equal(after.find('/Untouched').values['Completed'],42)
    equal(after.find('/Untouched').values['Keep'],b'original')
    equal(len(mount.state['commits']),1)
    raises(cleanup['retire_update_driver_process'],args=[session],message='already retired')




ordinary = testing.module("@stdlib//windows/servicing:registry.star")
ordinary_runtime = testing.module("@stdlib//windows/servicing:runtime.star")


def _ordinary_fixture(extra_retired_value=False):
    prefix = chr(92) + chr(92).join(["registry","machine","software"])
    old = "O:SYG:SYD:P(A;CI;KA;;;SY)"
    new = "O:SYG:SYD:P(A;CI;KR;;;SY)"
    records = []
    for tail, sides in [("Changed",["before","after"]),("Retired\\Child",["before"]),("New\\literal/part",["after"]),("AbsentUnchanged",["before","after"])]:
        for side in sides:
            records.append(dict(path=prefix+chr(92)+tail,side=side,identity="fixture",descriptor=dict(sddl=new if side=="after" else old),key_attributes={}))
    reduced = ordinary_runtime["reduce_servicing_registry_keys"](records)
    # Unchanged declaration must not materialize a missing physical key.
    for item in reduced.values():
        if item["path"].endswith("AbsentUnchanged"):
            item["after_descriptor"] = dict(sddl=old)
    changes = {p:p.endswith("retired\\child") or p.endswith("literal/part") for p,k in reduced.items() if k["explicit"]}
    keys = dict(system=ordinary_runtime["preprocess_servicing_registry_keys"](reduced,changes,{old:windows.compile_sddl(old),new:windows.compile_sddl(new)}),user={})
    value = (0,4,b"\x07\x00\x00\x00","false","",False)
    groups = {
        ("system",(prefix+"\\Retired\\Child").lower(),""):([value],[]),
        ("system",(prefix+"\\New\\literal/part").lower(),"number"):([],[value]),
    }
    current = windows.compile_sddl(old+"S:(ML;;0x1;;;S-1-16-8192)")
    patches = [dict(key="/Retired/Child",name="",type="REG_DWORD",value=7),dict(key="/Untouched",name="Keep",type="REG_BINARY",value=b"opaque")]
    if extra_retired_value:
        patches.append(dict(key="/Retired/Child",name="Foreign",type="REG_DWORD",value=9))
    source = windows.hive_from_patches("SOFTWARE",patches,keys=[dict(key="/",security=windows.compile_sddl(old)),dict(key="/Changed",security=current)])
    root = directory()
    path = "/Windows/System32/config/SOFTWARE"
    root.write(path,source)
    return root,path,keys,groups,current


def test_ordinary_key_security_and_physical_retirement():
    root,path,keys,groups,current = _ordinary_fixture()
    before = digest(root.find(path))
    result = ordinary["plan_update_ordinary_registry"](root,keys,groups,{0:0},"controlset001")
    equal(digest(root.find(path)),before)
    commit["apply_update_registry_effects"](root,result["plans"])
    hive = windows.hive(root.find(path))
    equal(hive.find(["Retired"]),None)
    equal(hive.find(["AbsentUnchanged"]),None)
    equal(hive.find(["Untouched"]).values,{"Keep":b"opaque"})
    equal(hive.find(["New","literal/part"]).values,{"number":7})
    equal(hive.find(["New","literal","part"]),None)
    security = windows.security_descriptor_parts(hive.find(["Changed"]).security)
    equal(security["control"],0x9c14)
    equal(windows.acl_entries(security["dacl"])["entries"][0]["mask"],0x20019)
    equal(security["sacl"],windows.security_descriptor_parts(current)["sacl"])
    equal(result["report"]["removed_keys"],2)
    equal(result["report"]["created_keys"],2)


def test_ordinary_unestablished_cleanup_rejects_without_publication():
    root,path,keys,groups,current = _ordinary_fixture(extra_retired_value=True)
    before = digest(root.find(path))
    raises(ordinary["plan_update_ordinary_registry"],args=[root,keys,groups,{0:0},"controlset001"],message="nonempty retired key requires")
    equal(digest(root.find(path)),before)


def test_ordinary_stale_hive_and_priority_ties_reject():
    root,path,keys,groups,current = _ordinary_fixture()
    result = ordinary["plan_update_ordinary_registry"](root,keys,groups,{0:0},"controlset001")
    root.write(path,windows.patch_hive(root.find(path),[dict(key="/Untouched",name="Concurrent",type="REG_DWORD",value=42)]))
    concurrent = digest(root.find(path))
    raises(commit["apply_update_registry_effects"],args=[root,result["plans"]],message="changed before commit")
    equal(digest(root.find(path)),concurrent)
    raises(ordinary["_registry_value_selection"],args=[[(0,4,b"one","false","",False),(1,4,b"two","false","",False)],{0:3,1:3}],message="family-bucket tie")



def test_ordinary_explicit_profile_values():
    path = chr(92) + chr(92).join(["registry","user","software","microsoft","uev","agent"])
    records = [dict(path=path,scope="user",side=side,identity="fixture",descriptor=None,key_attributes={}) for side in ["before","after"]]
    reduced = ordinary_runtime["reduce_servicing_registry_keys"](records,scope="user")
    user = ordinary_runtime["preprocess_servicing_registry_keys"](reduced,{path:True},{})
    keys = dict(system={},user=user)
    old,new = b"old",b"new"
    groups = {("user",path,"version"): ([(0,3,old,"true","",False)],[(0,3,new,"true","",False)])}
    root = directory()
    profiles = ["/Users/Default/NTUSER.DAT","/Users/Existing/NTUSER.DAT"]
    key = "/software/microsoft/uev/agent"
    security = windows.compile_sddl("O:SYG:SYD:P(A;CI;KA;;;SY)")
    for file,value in zip(profiles,[old,b"custom"]):
        root.write(file,windows.hive_from_patches("NTUSER",[dict(key=key,name="version",type="REG_BINARY",value=value)],keys=[dict(key=key,security=security)]))
    root.write("/Windows/System32/config/DEFAULT",root.find(profiles[0]))
    default_hash = digest(root.find("/Windows/System32/config/DEFAULT"))
    build = ordinary["plan_update_ordinary_registry"]
    args = [root,keys,groups,{0:0},"controlset001"]
    raises(build,args=args,message="explicit profile bindings")
    raises(build,args=args,kwargs=dict(profile_hives=[profiles[0],profiles[0].lower()]),message="duplicate")
    raises(build,args=args,kwargs=dict(profile_hives=["/Windows/System32/config/DEFAULT"]),message="canonical hive paths")
    result = build(root,keys,groups,{0:0},"controlset001",profile_hives=profiles)
    equal(windows.hive(root.find(profiles[0])).find(key).values["version"],old)
    commit["apply_update_registry_effects"](root,result["plans"])
    equal(windows.hive(root.find(profiles[0])).find(key).values["version"],new)
    equal(windows.hive(root.find(profiles[1])).find(key).values["version"],b"custom")
    equal(windows.hive(root.find(profiles[0])).find(key).security,security)
    equal(digest(root.find("/Windows/System32/config/DEFAULT")),default_hash)
    equal(result["report"]["set_values"],1)
    equal(result["report"]["preserved_values"],1)
    root.write(profiles[0],windows.hive_from_patches("NTUSER",[]))
    raises(build,args=args,kwargs=dict(profile_hives=[profiles[0]]),message="existing keys")


def test_driver_open_access_policy():
    policy = testing.module("@stdlib//windows/servicing:registry_access.star")["update_driver_key_open_access"]
    def access(sddl, mask):
        return policy(None, dict(security=windows.compile_sddl(sddl), access=mask))
    equal(access("O:BAG:SYD:(D;;KW;;;WD)(A;;KA;;;SY)", 0x2000000), 0xd0039)
    equal(access("O:BAG:SYD:(D;;KW;;;WD)(A;;KA;;;SY)", 0x40000000), None)
    equal(access("O:BAG:SYD:(A;;KR;;;SY)", 0x80000000), 0x20019)
    equal(access("O:BAG:SYD:(A;;KR;;;SY)", 0x2000002), None)
    equal(access("O:BAG:SYD:(A;IO;KA;;;SY)", 0x2000000), None)
    equal(access("O:SYG:SYD:", 0x2000000), 0x60000)
    equal(access("O:SYG:SYD:(A;;KR;;;OW)", 0x2000000), 0x20019)
    equal(access("O:BAG:SYD:(A;;KA;;;SY)(D;;KW;;;WD)", 0x2000000), 0xf003f)
    equal(access("O:BAG:SYD:(A;;KA;;;SY)S:(ML;;NW;;;S-1-16-12288)", 0x2000000), 0xf003f)
    raises(access, args=["O:BAG:SYD:(A;;KA;;;SY)S:(ML;;NW;;;S-1-16-16384)",0x2000000],message="integrity policy")
    raises(policy, args=[None,dict(security=None,access=0x2000000)],message="established key descriptor")


def test_driver_open_access_handle_lifetime():
    policy = testing.module("@stdlib//windows/servicing:registry_access.star")["update_driver_key_open_access"]
    abi = testing.module("@stdlib//windows/emulation:abi.star")
    descriptor = windows.compile_sddl("O:BAG:SYD:(A;;KR;;;SY)")
    source = windows.hive_from_patches("SOFTWARE", [], keys=[dict(key="/Access",security=descriptor)])
    for architecture in ["x86", "amd64"]:
        for native in [False, True]:
            registry = registry_policy["registry_plugin"](hives={"SOFTWARE":windows.hive(source)},on_open_key=policy)
            machine = emulator.machine(code=b"\xc3", architecture=architecture)
            machine.use(registry)
            output = machine.allocate(value=b"Z" * (machine.pointer_size+8))
            if native:
                layout = abi["object_attributes_layout"](machine.pointer_size)
                string = abi["counted_string_layout"](machine.pointer_size)
                raw = binary.encode(chr(92)+"Registry"+chr(92)+"Machine"+chr(92)+"SOFTWARE"+chr(92)+"Access",encoding="utf16le")
                name = machine.allocate(size=string["Size"])
                machine.write_u16le(name,len(raw))
                machine.write_u16le(name+2,len(raw))
                machine.write_pointer(name+string["Buffer"],machine.allocate(value=raw))
                obj = machine.allocate(size=layout["Size"])
                machine.write_u32le(obj,layout["Size"])
                machine.write_pointer(obj+layout["ObjectName"],name)
                address = machine.resolve_export("ntdll.dll",name="NtOpenKey")
                def invoke(mask):
                    return machine.call(address,args=[output,mask,obj])
            else:
                key = machine.allocate(value=binary.encode("SOFTWARE"+chr(92)+"Access",encoding="utf16le",nul=True))
                address = machine.resolve_export("advapi32.dll",name="RegOpenKeyExW")
                def invoke(mask):
                    return machine.call(address,args=[0x80000002,key,0,mask,output])
            first = registry.state["next_handle"]
            denied = invoke(2)
            equal(denied.reason,"return",denied.detail)
            equal(denied.value,0xc0000022 if native else 5)
            equal(registry.state["next_handle"],first)
            equal(machine.read(output,machine.pointer_size+8),b"Z"*(machine.pointer_size+8))
            opened = invoke(0x2000000)
            equal(opened.reason,"return",opened.detail)
            equal(opened.value,0)
            handle = machine.read_pointer(output)
            equal(registry.state["handle_access"][handle],0x20019)
            duplicate = registry._duplicate_handle(handle,0,False,2)
            equal(duplicate[0],0)
            equal(registry.state["handle_access"][duplicate[1]],0x20019)
            delete = machine.resolve_export("ntdll.dll",name="NtDeleteKey")
            equal(machine.call(delete,args=[duplicate[1]]).value,0xc0000022)
            # Overlay security, not the original hive or an earlier handle's
            # grant, is authoritative for a subsequent open.
            registry.set_key_security("SOFTWARE","/Access",windows.compile_sddl("O:BAG:SYD:(A;;KA;;;SY)"))
            equal(invoke(0x2000000).value,0)
            equal(registry.state["handle_access"][machine.read_pointer(output)],0xf003f)
            equal(registry.state["handle_access"][handle],0x20019)
            for opened_handle in list(registry.state["handles"]):
                registry._close_handle(opened_handle)


def test_driver_host_security_does_not_authorize_mounted_keys():
    mounts=testing.module("@stdlib//windows/servicing:driver_hives.star")
    policy=testing.module("@stdlib//windows/servicing:registry_access.star")["update_driver_key_open_access"]
    target_sd=windows.compile_sddl("O:BAG:SYD:(A;;KR;;;SY)")
    target=windows.hive_from_patches("SYSTEM",[],keys=[dict(key="/",security=target_sd)])
    host=windows.hive(windows.hive_from_patches("SYSTEM",[],keys=[dict(key="/",security=windows.compile_sddl("O:SYG:SYD:(A;;KA;;;SY)"))]))
    root=directory()
    root.write('/Windows/System32/config/SYSTEM',target)
    registry=registry_policy['registry_plugin'](on_open_key=policy)
    provider=mounts['update_driver_hive_mounts'](registry,root,{},host_namespace=host)
    registry.state['sources']['SOFTWARE']=provider
    # The mount source remains the authority even when the host is writable.
    provider.state['mounts']['restricted']=windows.hive(target)
    registry.load_keys([dict(hive='SOFTWARE',key='/Restricted')])
    machine=emulator.machine(code=b"\xc3",architecture='amd64')
    machine.use(registry)
    output=machine.allocate(size=8)
    def open_key(path):
        name=machine.allocate(value=binary.encode(path,encoding='utf16le',nul=True))
        result=machine.call(machine.resolve_export('advapi32.dll',name='RegOpenKeyExW'),args=[0x80000002,name,0,0x2000000,output])
        equal(result.reason,'return',result.detail)
        equal(result.value,0)
        handle=machine.read_pointer(output)
        access=registry.state['handle_access'][handle]
        registry._close_handle(handle)
        return access
    equal(open_key(''),0xf003f)
    equal(open_key('Restricted'),0x20019)
    equal(registry.effects(),dict(keys=[],key_deletions=[],values=[],value_deletions=[]))
    equal(digest(root.find('/Windows/System32/config/SYSTEM')),digest(target))

TEST_SUITE = suite("private/nt6_update_registry", [
    case("driver_host_security_isolation", test_driver_host_security_does_not_authorize_mounted_keys),
    case("driver_open_access_policy", test_driver_open_access_policy),
    case("driver_open_access_handles", test_driver_open_access_handle_lifetime),
    case("ordinary_security_and_retirement", test_ordinary_key_security_and_physical_retirement),
    case("ordinary_explicit_profile_values", test_ordinary_explicit_profile_values),
    case("ordinary_cleanup_preflight", test_ordinary_unestablished_cleanup_rejects_without_publication),
    case("ordinary_stale_and_tied", test_ordinary_stale_hive_and_priority_ties_reject),
    case("completed_host_retirement", test_completed_driver_host_retirement_persists_real_handles_and_rejects_early_close),
    case("recreated_objects", test_capture_commit_does_not_resurrect_deleted_objects),
    case("fail_closed", test_missing_security_and_unbound_mounts_fail_before_writes),
    case("mount_and_literal_parts", test_mount_translation_preserves_literal_parts_and_raw_value_types),
    case("literal_owner_deletion", test_literal_owner_leaf_deletions_do_not_remove_display_path_siblings),
    case("atomic_source_preflight", test_commit_preflights_all_hives_before_first_replacement),
    case("native_wmi_audit_security", test_wmi_autologger_creation_preserves_measured_audit_inheritance),
    case("native_eventlog_security", test_eventlog_creation_matches_actual_kernel_fixed_point),
    case("native_winevt_publisher_security", test_winevt_publisher_creation_matches_actual_kernel_fixed_point),
    case("native_device_property_security", test_device_property_creation_matches_native_protected_then_inherited_security),
    case("native_driver_key_security", test_driver_key_creation_matches_independent_kernel_capture),
    case("native_wudf_key_security", test_wudf_key_creation_matches_actual_kernel_fixed_point),
    case("native_components_owner_security", test_components_owner_creation_matches_independent_kernel_capture),
    case("native_owner_creation_privileges", test_native_owner_creation_requires_exact_descriptor_and_owned_privileges),
    case("native_mounted_object_name", test_mounted_object_name_uses_native_namespace_and_bounded_buffers),
    case("native_synchronous_unload", test_native_synchronous_unload_never_discards_live_references),
    case("native_incremental_flush", test_native_flush_deltas_do_not_replay_commits_or_lose_empty_recreation),
    case("native_open_reference_resize", test_native_open_reference_report_resizes_without_fabricating_entries),
    case("native_open_hive_flush", test_native_hive_flush_persists_with_open_references),
    case("driver_mount_epochs", test_driver_unmount_persists_before_namespace_teardown_and_remount),
    case("driver_mount_host_alias", test_driver_hive_mount_host_alias_retains_epoch_identity),
])
