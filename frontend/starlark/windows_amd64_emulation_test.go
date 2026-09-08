package starlarkfrontend

import (
	"testing"

	"go.starlark.net/starlark"
)

func TestAMD64ExplicitStop(t *testing.T) {
	architectureScript(t, `
def check(condition):
    if not condition:
        fail("explicit stop check failed")
machine = emulator.machine(architecture="amd64", code=b"\xc3")
state = {"calls": 0}
def callback(event):
    state["calls"] += 1
    if state["calls"] == 1:
        event.machine.stop("waiting", detail="input", value=0x123456789abcdef0)
    return 7
machine.hook(callback, address=machine.entry, argc=0)
result = machine.call(machine.entry)
check(result.reason == "waiting" and result.detail == "input" and result.value == 0x123456789abcdef0)
check(result.pc == machine.entry)
resumed = machine.run()
check(resumed.reason == "return" and resumed.value == 7 and state["calls"] == 2)

def invalid(event):
    event.machine.stop("return")
machine.hook(invalid, address=machine.entry, argc=0)
invalid_result = machine.call(machine.entry)
check(invalid_result.reason == "plugin" and "non-reserved reason" in invalid_result.detail)
`)
}

func TestRegistryHandlesAcrossArchitectures(t *testing.T) {
	thread, predeclared, err := newStarlarkRuntime("-")
	if err != nil {
		t.Fatal(err)
	}
	_, err = starlark.ExecFile(thread, "registry-architectures.star", `
load("@stdlib//windows/selfreg:registry.star", "registry_plugin")

def check(condition):
    if not condition:
        fail("registry architecture check failed")

def exercise(architecture):
    machine = emulator.machine(architecture=architecture, code=b"\xc3")
    registry = registry_plugin()
    machine.use(registry)
    path = machine.allocate(value=b"Software\\ArchitectureTest\x00")
    # Poison both halves: a successful Win64 PHKEY write must clear all
    # eight bytes, while Win32 must leave the following four bytes untouched.
    output = machine.allocate(value=b"\xaa" * 8)
    disposition = machine.allocate(size=4)
    root = 0xffffffff80000002 if architecture == "amd64" else 0x80000002
    create = machine.resolve_export("advapi32.dll", name="RegCreateKeyExA")
    result = machine.call(create,args=[root,path,0,0,0,0x20019,0,output,disposition])
    check(result.reason == "return" and result.value == 0)
    check(machine.read_u32le(disposition) == 1)
    if architecture == "amd64":
        handle = machine.read_u64le(output)
        check(handle < 0x100000000)
    else:
        handle = machine.read_u32le(output)
        check(machine.read_u32le(output+4) == 0xaaaaaaaa)
    value = machine.allocate(value=b"native\x00")
    set_value = machine.resolve_export("advapi32.dll",name="RegSetValueExA")
    # Win64 DWORDs do not own the high half of their argument slots. In
    # particular a native mov [rsp+28h],ecx leaves stale stack bytes above it.
    padding = 0x7420736900000000 if architecture == "amd64" else 0
    result = machine.call(set_value,args=[handle,0,0,padding|1,value,padding|7])
    check(result.reason == "return" and result.value == 0)
    check(len(registry.patches()) == 1)
    opened = registry.opens()[-1]
    check(registry.get_value(opened["hive"], opened["key"], "(default)") == "native")
    close = machine.resolve_export("advapi32.dll",name="RegCloseKey")
    result = machine.call(close,args=[handle])
    check(result.reason == "return" and result.value == 0)

exercise("x86")
exercise("amd64")
`, predeclared)
	if err != nil {
		if evaluation, ok := err.(*starlark.EvalError); ok {
			t.Fatal(evaluation.Backtrace())
		}
		t.Fatal(err)
	}
}

func architectureScript(t *testing.T, source string) {
	t.Helper()
	thread, predeclared, err := newStarlarkRuntime("-")
	if err != nil {
		t.Fatal(err)
	}
	_, err = starlark.ExecFile(thread, "architectures.star", source, predeclared)
	if err != nil {
		if evaluation, ok := err.(*starlark.EvalError); ok {
			t.Fatal(evaluation.Backtrace())
		}
		t.Fatal(err)
	}
}

func TestRegistrationGeneratedEntries(t *testing.T) {
	thread, predeclared, err := newStarlarkRuntime("-")
	if err != nil {
		t.Fatal(err)
	}
	predeclared["image"] = relocatablePE32TestImage(t, 0x200000)
	_, err = starlark.ExecFile(thread, "generated-entries.star", `
load("@stdlib//windows/emulation:runner.star", "run")
def execute(machine):
    path = machine.allocate(value=binary.encode("C:\\root\\new.txt\x00",encoding="utf16le"))
    opened = machine.call(machine.resolve_export("kernel32.dll",name="CreateFileW"),args=[path,0x40000000,0,0,2,0x80,0])
    if opened.reason != "return" or opened.value == 0xffffffff:
        fail("file creation failed")
    data = machine.allocate(value=b"hello")
    written = machine.allocate(size=4)
    result = machine.call(machine.resolve_export("kernel32.dll",name="WriteFile"),args=[opened.value,data,5,written,0])
    if result.reason != "return" or result.value != 1:
        fail("file write failed")
    name = machine.allocate(value=binary.encode("C:\\root\\empty\x00",encoding="utf16le"))
    return machine.call(machine.resolve_export("kernel32.dll",name="CreateDirectoryW"),args=[name,0])
def check():
    result = run(binary.concat([image]),"example.dll",directories=["C:\\root"],execute=execute)
    if result["result"].reason != "return" or result["result"].value != 1:
        fail("directory creation failed")
    entries = dict(result["generated_entries"])
    entry = entries.pop("c:\\root\\new.txt")
    if entry["directory"] or entry["data"] != b"hello":
        fail("generated file entry lost content")
    if entries != {"c:\\root\\empty": {"directory": True}}:
        fail("generated entries must retain empty directories and exclude initial paths")
    if result["generated_files"] != {"c:\\root\\new.txt": b"hello"}:
        fail("legacy file outputs must agree with entries and exclude directories")
check()
`, predeclared)
	if err != nil {
		if evaluation, ok := err.(*starlark.EvalError); ok {
			t.Fatal(evaluation.Backtrace())
		}
		t.Fatal(err)
	}
}

func TestCountedStringInitializationAcrossArchitectures(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:win32.star", "kernel32_plugin")
load("@stdlib//windows/emulation:abi.star", "counted_string_layout")
def check(condition):
    if not condition:
        fail("counted string architecture check failed")
def exercise(architecture):
    machine = emulator.machine(architecture=architecture,code=b"\xc3")
    machine.use(kernel32_plugin())
    layout = counted_string_layout(machine.pointer_size)
    check(layout["Buffer"] == machine.pointer_size)
    check(layout["Size"] == machine.pointer_size*2)
    descriptor = machine.allocate(value=b"\xaa" * (layout["Size"]+4))
    for name, data, length, terminator in [
        ("RtlInitUnicodeString", b"A\x00\x3d\xd8\x00\xde\x00\x00", 6, 2),
        ("RtlInitAnsiString", b"native\x00", 6, 1),
    ]:
        source = machine.allocate(value=data)
        api = machine.resolve_export("ntdll.dll",name=name)
        result = machine.call(api,args=[descriptor,source])
        check(result.reason == "return")
        check(machine.read_u16le(descriptor) == length)
        check(machine.read_u16le(descriptor+2) == length+terminator)
        check(machine.read_pointer(descriptor+layout["Buffer"]) == source)
        check(machine.read_u32le(descriptor+layout["Size"]) == 0xaaaaaaaa)
        if machine.pointer_size == 8:
            check(machine.read_u32le(descriptor+4) == 0xaaaaaaaa)
        result = machine.call(api,args=[descriptor,0])
        check(result.reason == "return")
        check(machine.read_u32le(descriptor) == 0)
        check(machine.read_pointer(descriptor+layout["Buffer"]) == 0)
exercise("x86")
exercise("amd64")
`)
}

func TestProcessMemoryProtectionAcrossArchitectures(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:crypto.star", "cryptoapi_plugin")
def check(condition):
    if not condition:
        fail("memory protection check failed")
def exercise(architecture):
    machine = emulator.machine(architecture=architecture,code=b"\xc3")
    machine.use(cryptoapi_plugin(memory_protection_key=b"0123456789abcdef"))
    protect = machine.resolve_export("advapi32.dll",name="SystemFunction040")
    unprotect = machine.resolve_export("advapi32.dll",name="SystemFunction041")
    plain = b"abcdefgh" * 3
    buffer = machine.allocate(value=plain)
    result = machine.call(protect,args=[buffer,24,0])
    check(result.reason == "return" and result.value == 0)
    encrypted = machine.read(buffer,24)
    check(encrypted != plain)
    copied = machine.allocate(value=encrypted)
    result = machine.call(unprotect,args=[copied,24,0])
    check(result.reason == "return" and result.value == 0)
    check(machine.read(copied,24) == plain)
    check(machine.read(buffer,24) == encrypted)
    other = emulator.machine(architecture=architecture,code=b"\xc3")
    other.use(cryptoapi_plugin(memory_protection_key=b"fedcba9876543210"))
    foreign = other.allocate(value=encrypted)
    result = other.call(other.resolve_export("advapi32.dll",name="SystemFunction041"),args=[foreign,24,0])
    check(result.reason == "return" and other.read(foreign,24) != plain)
    for size, options, status in [(23,0,0xc000000d),(24,3,0xc000000d),(24,1,0xc00000bb),(24,2,0xc00000bb),(24,4,0xc00000bb)]:
        result = machine.call(protect,args=[buffer,size,options])
        check(result.reason == "return" and result.value == status)
        check(machine.read(buffer,24) == encrypted)
    for size in [0,8,16,24]:
        machine.write(buffer,plain)
        check(machine.call(protect,args=[buffer,size,0]).value == 0)
        check(machine.call(unprotect,args=[buffer,size,0]).value == 0)
        check(machine.read(buffer,24) == plain)
exercise("x86")
exercise("amd64")
`)
}

func TestCOMAllocatorAcrossArchitectures(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:win32.star", "ole32_plugin")
def check(condition):
    if not condition:
        fail("COM allocator architecture check failed")
def exercise(architecture):
    machine = emulator.machine(architecture=architecture,code=b"\xc3")
    machine.use(ole32_plugin())
    output = machine.allocate(value=b"\xaa"*16)
    result = machine.call(machine.resolve_export("ole32.dll",name="CoGetMalloc"),args=[1,output])
    check(result.reason == "return" and result.value == 0)
    interface = machine.read_pointer(output)
    vtable = machine.read_pointer(interface)
    allocate = machine.read_pointer(vtable+3*machine.pointer_size)
    get_size = machine.read_pointer(vtable+6*machine.pointer_size)
    free = machine.read_pointer(vtable+5*machine.pointer_size)
    result = machine.call(allocate,args=[interface,37])
    check(result.reason == "return" and result.value != 0)
    block = result.value
    machine.write(block,b"native allocator")
    check(machine.call(get_size,args=[interface,block]).value == 37)
    check(machine.call(free,args=[interface,block]).reason == "return")
    check(machine.call(get_size,args=[interface,block]).value == (1 << (machine.pointer_size*8))-1)
    check(machine.read_u32le(output+machine.pointer_size) == 0xaaaaaaaa)
exercise("x86")
exercise("amd64")
`)
}

func TestDOSNTPathConversionAcrossArchitectures(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:win32.star", "kernel32_plugin", "security_plugin")
load("@stdlib//windows/emulation:abi.star", "counted_string_layout")
def check(condition):
    if not condition:
        fail("DOS/NT path architecture check failed")
def exercise(architecture):
    machine = emulator.machine(architecture=architecture,code=b"\xc3")
    kernel = kernel32_plugin(environment={"CurrentDirectory":"C:\\work\\sub"})
    machine.use([kernel,security_plugin(kernel=kernel)])
    layout = counted_string_layout(machine.pointer_size)
    descriptor = machine.allocate(value=b"\xaa" * (layout["Size"]+8))
    part = machine.allocate(value=b"\xaa"*16)
    relative_size = layout["Size"] + 2*machine.pointer_size
    relative = machine.allocate(value=b"\xaa"*(relative_size+8))
    convert = machine.resolve_export("ntdll.dll",name="RtlDosPathNameToRelativeNtPathName_U")
    release = machine.resolve_export("ntdll.dll",name="RtlFreeUnicodeString")
    for source, expected in [
        ("C:\\Windows\\All Users\\Application Data\\Microsoft", "\\??\\C:\\Windows\\All Users\\Application Data\\Microsoft"),
        ("..\\file.txt", "\\??\\C:\\work\\file.txt"),
        ("\\root\\file", "\\??\\C:\\root\\file"),
        ("D:file", "\\??\\D:\\file"),
        ("\\\\server\\share\\folder\\..\\file", "\\??\\UNC\\server\\share\\file"),
        ("\\\\?\\C:\\folder\\..\\file", "\\??\\C:\\folder\\..\\file"),
        ("C:\\", "\\??\\C:\\"),
    ]:
        input = machine.allocate(value=binary.encode(source+"\x00",encoding="utf16le"))
        result = machine.call(convert,args=[input,descriptor,part,relative])
        check(result.reason == "return" and result.value == 1)
        buffer = machine.read_pointer(descriptor+layout["Buffer"])
        check(machine.read_cstring(buffer,encoding="utf16le") == expected)
        check(machine.read_u16le(descriptor) == len(binary.encode(expected,encoding="utf16le")))
        check(buffer in kernel.state["local_allocations"])
        if expected.endswith("\\"):
            check(machine.read_pointer(part) == 0)
        else:
            check(machine.read_cstring(machine.read_pointer(part),encoding="utf16le") == expected.rsplit("\\",1)[-1])
        check(machine.read(relative,relative_size) == b"\x00"*relative_size)
        check(machine.read_u32le(relative+relative_size) == 0xaaaaaaaa)
        check(machine.call(release,args=[descriptor]).reason == "return")
        check(buffer not in kernel.state["local_allocations"])
        check(machine.read_pointer(descriptor+layout["Buffer"]) == 0)
        check(machine.read_u32le(descriptor+layout["Size"]) == 0xaaaaaaaa)
        machine.free(input)
    check(machine.call(convert,args=[0,descriptor,part,relative]).value == 0)
exercise("x86")
exercise("amd64")
`)
}

func TestNTFileCreationAcrossArchitectures(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:win32.star", "kernel32_plugin")
load("@stdlib//windows/emulation:abi.star", "counted_string_layout", "object_attributes_layout", "security_descriptor_layout")
def check(condition):
    if not condition:
        fail("NT file creation architecture check failed")
def exercise(architecture):
    machine = emulator.machine(architecture=architecture,code=b"\xc3")
    kernel = kernel32_plugin(directories=["C:\\root"])
    machine.use(kernel)
    layout = object_attributes_layout(machine.pointer_size)
    descriptor = machine.allocate(size=counted_string_layout(machine.pointer_size)["Size"])
    attrs = machine.allocate(size=layout["Size"])
    output = machine.allocate(value=b"\xaa"*16)
    io = machine.allocate(value=b"\xaa"*24)
    machine.write_u32le(attrs+layout["Length"],layout["Size"])
    machine.write_pointer(attrs+layout["ObjectName"],descriptor)
    machine.write_u32le(attrs+layout["Attributes"],0x40)
    init = machine.resolve_export("ntdll.dll",name="RtlInitUnicodeString")
    create = machine.resolve_export("ntdll.dll",name="NtCreateFile")
    close = machine.resolve_export("ntdll.dll",name="NtClose")
    padding = 0x7420736900000000 if architecture == "amd64" else 0
    def select(path, root=0):
        value = machine.allocate(value=binary.encode(path+"\x00",encoding="utf16le"))
        check(machine.call(init,args=[descriptor,value]).reason == "return")
        machine.write_pointer(attrs+layout["RootDirectory"],root)
    def make(disposition,options,share=3):
        result = machine.call(create,args=[output,0x100003,attrs,io,0,padding|0x80,padding|share,padding|disposition,padding|options,0,0])
        check(result.reason == "return")
        check(machine.read_u32le(io) == result.value)
        check(machine.read_u32le(io+2*machine.pointer_size) == 0xaaaaaaaa)
        check(machine.read_u32le(output+machine.pointer_size) == 0xaaaaaaaa)
        return result.value
    select("\\??\\C:\\root\\child")
    check(make(2,0x4021) == 0)
    directory = machine.read_pointer(output)
    check(machine.read_pointer(io+machine.pointer_size) == 2)
    check(kernel.state["paths"]["c:\\root\\child"]["directory"])
    check(make(2,0x4021) == 0xc0000035)
    check(machine.read_pointer(io+machine.pointer_size) == 4)
    select("file.bin",root=directory)
    check(make(3,0x60,share=0) == 0)
    file = machine.read_pointer(output)
    check(make(1,0x60) == 0xc0000043)
    payload = machine.allocate(value=b"body")
    written = machine.allocate(size=4)
    write = machine.resolve_export("kernel32.dll",name="WriteFile")
    result = machine.call(write,args=[file,payload,4,written,0])
    check(result.reason == "return" and result.value == 1)
    check(kernel.state["paths"]["c:\\root\\child\\file.bin"]["data"] == b"body")
    check(machine.call(close,args=[file]).value == 0)
    check(make(4,0x60) == 0)
    check(machine.read_pointer(io+machine.pointer_size) == 3)
    check(kernel.state["paths"]["c:\\root\\child\\file.bin"]["data"] == b"")
    check(machine.call(close,args=[machine.read_pointer(output)]).value == 0)
    select("\\??\\C:\\missing\\child")
    check(make(2,0x21) == 0xc000003a)
    check("c:\\missing\\child" not in kernel.state["paths"])
    select("\\??\\C:\\root\\absent.bin")
    check(make(1,0x60) == 0xc0000034)
    sd_layout = security_descriptor_layout(machine.pointer_size)
    sd = machine.allocate(size=sd_layout["Size"])
    acl_bytes = b"\x02\x00\x1c\x00\x01\x00\x00\x00\x00\x00\x14\x00\x9f\x01\x12\x00\x01\x01\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00"
    acl = machine.allocate(value=acl_bytes)
    machine.write(sd,b"\x01\x00\x04\x00")
    machine.write_pointer(sd+sd_layout["Dacl"],acl)
    machine.write_pointer(attrs+layout["SecurityDescriptor"],sd)
    select("\\??\\C:\\root\\secured")
    check(make(2,0x4021) == 0)
    check(machine.call(close,args=[machine.read_pointer(output)]).value == 0)
    security = kernel.state["paths"]["c:\\root\\secured"]["security"]
    check(security[:4] == b"\x01\x00\x04\x80" and security[16:20] == b"\x14\x00\x00\x00")
    check(security[20:] == acl_bytes)
    # Caller memory is transient; changing or freeing it cannot alter the file.
    machine.write(acl,b"\x00"*len(acl_bytes))
    check(kernel.state["paths"]["c:\\root\\secured"]["security"] == security)
    select("\\??\\C:\\root\\invalid")
    check(make(2,0x4021) == 0xc0000079)
    check("c:\\root\\invalid" not in kernel.state["paths"])
    relative = machine.allocate(value=security)
    machine.write_pointer(attrs+layout["SecurityDescriptor"],relative)
    select("\\??\\C:\\root\\relative")
    check(make(2,0x4021) == 0)
    check(kernel.state["paths"]["c:\\root\\relative"]["security"] == security)
exercise("x86")
exercise("amd64")
`)
}

func TestSecurityDescriptorAcrossArchitectures(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:win32.star", "security_plugin")
load("@stdlib//windows/emulation:abi.star", "security_descriptor_layout")
def check(condition):
    if not condition:
        fail("security descriptor architecture check failed")
def exercise(architecture):
    machine = emulator.machine(architecture=architecture,code=b"\xc3")
    machine.use(security_plugin())
    def call(name,args):
        result = machine.call(machine.resolve_export("advapi32.dll",name=name),args=args)
        check(result.reason == "return")
        return result.value
    layout = security_descriptor_layout(machine.pointer_size)
    check(layout["Size"] == (40 if architecture == "amd64" else 20))
    sd = machine.allocate(value=b"\xaa"*(layout["Size"]+4))
    check(call("InitializeSecurityDescriptor",[sd,1]) == 1)
    check(machine.read(sd+layout["Size"],4) == b"\xaa"*4)
    owner = machine.allocate(value=b"\x01\x01\x00\x00\x00\x00\x00\x05\x12\x00\x00\x00")
    acl = machine.allocate(value=b"\x02\x00\x08\x00\x00\x00\x00\x00")
    check(call("SetSecurityDescriptorOwner",[sd,owner,1]) == 1)
    check(call("SetSecurityDescriptorDacl",[sd,1,acl,0]) == 1)
    check(machine.read_pointer(sd+layout["Owner"]) == owner)
    check(machine.read_pointer(sd+layout["Dacl"]) == acl)
    output = machine.allocate(value=b"\xaa"*(machine.pointer_size+4))
    defaulted = machine.allocate(size=4)
    present = machine.allocate(size=4)
    check(call("GetSecurityDescriptorOwner",[sd,output,defaulted]) == 1)
    check(machine.read_pointer(output) == owner and machine.read_u32le(defaulted) == 1)
    check(machine.read(output+machine.pointer_size,4) == b"\xaa"*4)
    check(call("GetSecurityDescriptorDacl",[sd,present,output,defaulted]) == 1)
    check(machine.read_pointer(output) == acl and machine.read_u32le(present) == 1)
    capacity = machine.allocate(size=4)
    check(call("MakeSelfRelativeSD",[sd,0,capacity]) == 0)
    check(machine.read_u32le(capacity) == 40)
    relative = machine.allocate(size=40)
    check(call("MakeSelfRelativeSD",[sd,relative,capacity]) == 1)
    check(machine.read_u32le(relative+4) == 20 and machine.read_u32le(relative+16) == 32)
    check(call("GetSecurityDescriptorOwner",[relative,output,defaulted]) == 1)
    check(machine.read_pointer(output) == relative+20)
    check(call("GetSecurityDescriptorLength",[relative]) == 40)
    absolute_capacity = machine.allocate(value=b"\x00"*4)
    owner_capacity = machine.allocate(size=4)
    acl_capacity = machine.allocate(size=4)
    check(call("MakeAbsoluteSD",[relative,0,absolute_capacity,0,acl_capacity,0,0,0,owner_capacity,0,0]) == 0)
    check(machine.read_u32le(absolute_capacity) == layout["Size"])
    restored = machine.allocate(value=b"\xaa"*(layout["Size"]+4))
    restored_owner = machine.allocate(size=12)
    restored_acl = machine.allocate(size=8)
    check(call("MakeAbsoluteSD",[relative,restored,absolute_capacity,restored_acl,acl_capacity,0,0,restored_owner,owner_capacity,0,0]) == 1)
    check(machine.read_pointer(restored+layout["Owner"]) == restored_owner)
    check(machine.read(restored_owner,12) == machine.read(owner,12))
    check(machine.read_pointer(restored+layout["Dacl"]) == restored_acl)
    check(machine.read(restored_acl,8) == machine.read(acl,8))
    check(machine.read(restored+layout["Size"],4) == b"\xaa"*4)
exercise("x86")
exercise("amd64")
`)
}

func TestAllocatedSIDAcrossArchitectures(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:win32.star", "security_plugin")
def check(condition):
    if not condition:
        fail("allocated SID architecture check failed")
def exercise(architecture):
    machine = emulator.machine(architecture=architecture,code=b"\xc3")
    machine.use(security_plugin())
    authority = machine.allocate(value=b"\x00\x00\x00\x00\x00\x05")
    poison = 0x1234567800000000 if architecture == "amd64" else 0
    for dll, name, expected in [("advapi32.dll","AllocateAndInitializeSid",1),("ntdll.dll","RtlAllocateAndInitializeSid",0)]:
        output = machine.allocate(value=b"\xaa"*(machine.pointer_size+4))
        call = machine.resolve_export(dll,name=name)
        result = machine.call(call,args=[authority,poison|2,poison|32,poison|544,0,0,0,0,0,0,output])
        check(result.reason == "return" and result.value == expected)
        address = machine.read_pointer(output)
        check(machine.read(address,16) == b"\x01\x02\x00\x00\x00\x00\x00\x05\x20\x00\x00\x00\x20\x02\x00\x00")
        check(machine.read(output+machine.pointer_size,4) == b"\xaa"*4)
exercise("x86")
exercise("amd64")
`)
}

func TestAMD64MappingRecords(t *testing.T) {
	architectureScript(t, `
def check(condition):
    if not condition:
        fail("mapping record check failed")
machine = emulator.machine(architecture="amd64",code=b"\xc3")
address = machine.allocate(size=32,name="named allocation")
machine.protect(address+8,8,readable=True,writable=False,executable=True)
entries = [entry for entry in machine.mappings if entry.allocation_base == address]
check([(e.start,e.size,e.readable,e.writable,e.executable,e.name) for e in entries] == [
    (address,8,True,True,False,"named allocation"),
    (address+8,8,True,False,True,"named allocation"),
    (address+16,16,True,True,False,"named allocation"),
])
snapshot = machine.snapshot()
machine.free(address)
check(len([entry for entry in machine.mappings if entry.allocation_base == address]) == 0)
check(len([entry for entry in snapshot.mappings if entry.allocation_base == address]) == 3)
`)
}

func TestSystemInfoAcrossArchitectures(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:win32.star", "kernel32_plugin")
load("@stdlib//windows/emulation:abi.star", "system_info_layout")
def check(condition):
    if not condition:
        fail("SYSTEM_INFO architecture check failed")
def exercise(architecture):
    machine = emulator.machine(architecture=architecture,code=b"\xc3")
    machine.use(kernel32_plugin())
    layout = system_info_layout(machine.pointer_size)
    amd64 = architecture == "amd64"
    check(layout["Size"] == (48 if amd64 else 36))
    check(layout["AllocationGranularity"] == (40 if amd64 else 28))
    for name in ["GetSystemInfo","GetNativeSystemInfo"]:
        output = machine.allocate(value=b"\xaa"*(layout["Size"]+8))
        result = machine.call(machine.resolve_export("kernel32.dll",name=name),args=[output])
        check(result.reason == "return")
        check(machine.read_u16le(output+layout["ProcessorArchitecture"]) == (9 if amd64 else 0))
        check(machine.read_u32le(output+layout["PageSize"]) == 4096)
        check(machine.read_u32le(output+layout["AllocationGranularity"]) == 65536)
        check(machine.read_u32le(output+layout["NumberOfProcessors"]) == 1)
        check(machine.read_pointer(output+layout["MinimumApplicationAddress"]) == 65536)
        check(machine.read_pointer(output+layout["MaximumApplicationAddress"]) == (0x7ffffffeffff if amd64 else 0x7ffeffff))
        check(machine.read_pointer(output+layout["ActiveProcessorMask"]) == 1)
        check(machine.read_u16le(output+layout["Reserved"]) == 0)
        check(machine.read(output+layout["Size"],8) == b"\xaa"*8)
exercise("x86")
exercise("amd64")
`)
}

func TestKernelEnvironmentAcrossArchitectures(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:win32.star", "kernel32_plugin", "environment_plugin", "msvcrt_plugin")
load("@stdlib//windows/emulation:abi.star", "teb_layout", "process_layout")
def check(condition):
    if not condition:
        fail("kernel environment architecture check failed")
def exercise(architecture):
    options = {"gs_base": 0x700000000} if architecture == "amd64" else {"fs_base": 0x7ffde000}
    machine = emulator.machine(architecture=architecture, code=b"\xb8\x07\x00\x00\x00\xc3", **options)
    kernel = kernel32_plugin(module_path="C:\\WINDOWS\\system32\\native.dll")
    environment = environment_plugin({"SystemRoot": "C:\\WINDOWS"})
    crt = msvcrt_plugin(kernel=kernel)
    machine.use([kernel, environment, crt])
    layout = teb_layout(machine.pointer_size)
    fields = layout["fields"]
    teb = machine.segment_base(layout["segment"])
    check(machine.read_pointer(teb+fields["Self"]) == teb)
    check(machine.read_pointer(teb+fields["StackBase"]) == machine.stack.high)
    process = process_layout(machine.pointer_size)
    peb = machine.read_pointer(teb+fields["ProcessEnvironmentBlock"])
    parameters = machine.read_pointer(peb+process["peb"]["ProcessParameters"])
    block = machine.read_pointer(parameters+process["parameters"]["Environment"])
    check(machine.read_cstring(block,encoding="utf16le") == "SystemRoot=C:\\WINDOWS")
    check(machine.read_u8(peb+2) == 0)
    tls_alloc = machine.resolve_export("kernel32.dll",name="TlsAlloc")
    tls_set = machine.resolve_export("kernel32.dll",name="TlsSetValue")
    tls_get = machine.resolve_export("kernel32.dll",name="TlsGetValue")
    slot = machine.call(tls_alloc).value
    pointer = 0x100000001 if architecture == "amd64" else 0x10000001
    check(machine.call(tls_set,args=[slot,pointer]).value == 1)
    slots = machine.read_pointer(teb+fields["ThreadLocalStoragePointer"])
    check(machine.read_pointer(slots+slot*machine.pointer_size) == pointer)
    check(machine.call(tls_get,args=[slot]).value == pointer)
    get_process = machine.resolve_export("kernel32.dll",name="GetCurrentProcess")
    process_handle = machine.call(get_process).value
    check(process_handle == (1 << (machine.pointer_size*8))-1)
    basename = machine.resolve_export("psapi.dll",name="GetModuleBaseNameA")
    output = machine.allocate(size=64)
    check(machine.call(basename,args=[process_handle,0,output,64]).value == len("native.dll"))
    check(machine.read_cstring(output) == "native.dll")
    check(machine.call(basename,args=[123,0,output,64]).value == 0)
    check(kernel.state["last_error"] == 6)
    command_line = machine.resolve_export("msvcrt.dll",name="_acmdln")
    check(machine.read_cstring(machine.read_pointer(command_line)) == "regsvr32.exe")
    table = machine.allocate(size=machine.pointer_size)
    machine.write_pointer(table,machine.entry)
    initterm = machine.resolve_export("msvcrt.dll",name="_initterm_e")
    result = machine.call(initterm,args=[table,table+machine.pointer_size])
    check(result.reason == "return" and result.value == 7)
    if architecture == "amd64":
        probe = machine.resolve_export("kernel32.dll",name="__chkstk")
        machine.set_register("rax",8193)
        machine.set_register("r8",0x123456789)
        checked = machine.call(probe)
        check(checked.reason == "return" and checked.value == 8193)
        check(machine.get_register("r8") == 0x123456789)
        machine.set_register("rax",machine.stack.high-machine.stack.low+1)
        checked = machine.call(probe)
        check(checked.reason == "plugin" and "stack budget" in checked.detail)
exercise("x86")
exercise("amd64")
`)
}

func TestNativeComponentCategoryRegistration(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:registry.star", "registry_plugin")
load("@stdlib//windows/selfreg:comcat.star", "component_categories_provider")
load("@stdlib//windows/selfreg:win32.star", "ole32_plugin")
def exercise(architecture):
    machine = emulator.machine(architecture=architecture,code=b"\xc3")
    registry = registry_plugin()
    provider = component_categories_provider(registry)
    ole = ole32_plugin(class_activators={provider["classes"][0]:provider["activate"]})
    machine.use(ole)
    tail = b"\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"
    clsid = machine.allocate(value=binary.concat([b"\x05\xe0\x02\x00",tail]))
    iid = machine.allocate(value=binary.concat([b"\x12\xe0\x02\x00",tail]))
    output = machine.allocate(value=b"\xaa"*(machine.pointer_size+4))
    result = machine.call(machine.resolve_export("ole32.dll",name="CoCreateInstance"),args=[clsid,0,1,iid,output])
    if result.reason != "return" or result.value != 0:
        fail("native component manager activation failed: "+result.detail)
    interface = machine.read_pointer(output)
    if machine.read(output+machine.pointer_size,4) != b"\xaa"*4 or ole.state["activations"][-1]["interface_pointer"] != interface:
        fail("activation output pointer or guard corrupted")
    def invoke(slot,args):
        target = machine.read_pointer(machine.read_pointer(interface)+slot*machine.pointer_size)
        result = machine.call(target,args=[interface]+args)
        if result.reason != "return":
            fail(result.detail)
        return result.value
    if invoke(0,[iid,output]) != 0 or machine.read_pointer(output) != interface:
        fail("native QueryInterface identity lost")
    class_id = machine.allocate(value=b"\x11"*16)
    category = machine.allocate(value=b"\x22"*16)
    count = 0x123400000001 if architecture == "amd64" else 1
    if invoke(5,[class_id,count,category]) != 0:
        fail("category registration failed")
    key = "/Classes/CLSID/{11111111-1111-1111-1111-111111111111}/Implemented Categories/{22222222-2222-2222-2222-222222222222}"
    if registry.get_value("SOFTWARE",key,"(default)",None) != "":
        fail("category registration effect missing")
    if invoke(2,[]) != 1 or invoke(2,[]) != 0:
        fail("native interface reference counting failed")
exercise("x86")
exercise("amd64")
`)
}

func TestLegacyRegistrySetValueIgnoresSize(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:registry.star", "registry_plugin")
def exercise(architecture,suffix,encoding):
    machine = emulator.machine(architecture=architecture,code=b"\xc3")
    registry = registry_plugin()
    machine.use(registry)
    key = machine.allocate(value=binary.encode("Example",encoding=encoding,nul=True))
    data = machine.allocate(value=binary.encode("Complete string",encoding=encoding,nul=True))
    root = 0xffffffff80000000 if architecture == "amd64" else 0x80000000
    target = machine.resolve_export("advapi32.dll",name="RegSetValue"+suffix)
    for size in [0,1,0xffffffffffffffff if architecture == "amd64" else 0xffffffff]:
        result = machine.call(target,args=[root,key,1,data,size])
        if result.reason != "return" or result.value != 0:
            fail("RegSetValue consumed ignored byte count")
        if registry.get_value("SOFTWARE","/Classes/Example","(default)") != "Complete string":
            fail("RegSetValue truncated NUL-terminated text")
    if machine.call(target,args=[root,key,4,data,4]).value != 87 or machine.call(target,args=[root,key,1,0,0]).value != 87:
        fail("RegSetValue accepted invalid type or NULL data")
exercise("x86","A","ascii")
exercise("x86","W","utf16le")
exercise("amd64","A","ascii")
exercise("amd64","W","utf16le")
`)
}

func TestCRTOperatorAllocationAcrossArchitectures(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:win32.star", "msvcrt_plugin")
def exercise(architecture,new_name,delete_name):
    machine = emulator.machine(architecture=architecture,code=b"\xc3")
    crt = msvcrt_plugin()
    machine.use(crt)
    result = machine.call(machine.resolve_export("msvcrt.dll",name=new_name),args=[48])
    if result.reason != "return" or not result.value:
        fail("operator new failed")
    pointer = result.value
    if architecture == "amd64" and pointer <= 0xffffffff:
        fail("native allocation test did not exercise high pointer bits")
    machine.write(pointer,b"x"*48)
    if pointer not in crt.state["allocations"]:
        fail("operator new did not track ownership")
    result = machine.call(machine.resolve_export("msvcrt.dll",name=delete_name),args=[pointer])
    if result.reason != "return" or pointer in crt.state["allocations"]:
        fail("operator delete did not release native allocation")
exercise("x86","??2@YAPAXI@Z","??3@YAXPAX@Z")
exercise("amd64","??2@YAPEAX_K@Z","??3@YAXPEAX@Z")
`)
}

func TestServiceDescriptionNativePointers(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:service.star", "service_manager_plugin")
load("@stdlib//windows/selfreg:registry.star", "registry_plugin")
def exercise(architecture,suffix,encoding):
    machine = emulator.machine(architecture=architecture,code=b"\xc3")
    machine.use(service_manager_plugin(registry_plugin()))
    def call(name,args):
        result = machine.call(machine.resolve_export("advapi32.dll",name=name+suffix),args=args)
        if result.reason != "return":
            fail(result.detail)
        return result.value
    manager = call("OpenSCManager",[0,0,0])
    name = machine.allocate(value=binary.encode("ExampleSvc",encoding=encoding,nul=True))
    path = machine.allocate(value=binary.encode("C:\\example.exe",encoding=encoding,nul=True))
    service = call("CreateService",[manager,name,0,0,0x10,2,1,path,0,0,0,0,0])
    description = "Example service"
    encoded = binary.encode(description,encoding=encoding,nul=True)
    text = machine.allocate(value=encoded)
    info = machine.allocate(size=machine.pointer_size)
    machine.write_pointer(info,text)
    if call("ChangeServiceConfig2",[service,1,info]) != 1:
        fail("change description failed")
    required = machine.allocate(value=b"\xaa"*8)
    if call("QueryServiceConfig2",[service,1,0,0,required]) != 0:
        fail("accepted absent query buffer")
    size = machine.read_u32le(required)
    if size != machine.pointer_size+len(encoded) or machine.read(required+4,4) != b"\xaa"*4:
        fail("incorrect native description size or DWORD length output")
    output = machine.allocate(value=b"\xaa"*(size+4))
    if call("QueryServiceConfig2",[service,1,output,size,required]) != 1:
        fail("query description failed")
    if machine.read_pointer(output) != output+machine.pointer_size or machine.read_cstring(machine.read_pointer(output),encoding=encoding) != description or machine.read(output+size,4) != b"\xaa"*4:
        fail("description pointer or output guard corrupted")
exercise("x86","A","ascii")
exercise("x86","W","utf16le")
exercise("amd64","A","ascii")
exercise("amd64","W","utf16le")
`)
}

func TestCRTVariadicRegisterAndStackArguments(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:win32.star", "msvcrt_plugin")
def exercise(architecture):
    machine = emulator.machine(architecture=architecture,code=b"\xc3")
    machine.use(msvcrt_plugin())
    output = machine.allocate(size=128)
    format = machine.allocate(value=b"%s/%s/%s/%s/%s\x00")
    pointers = [machine.allocate(value=binary.encode(value,nul=True)) for value in ["one","two","three","four","five"]]
    result = machine.call(machine.resolve_export("msvcrt.dll",name="_snprintf"),args=[output,128,format]+pointers)
    expected = "one/two/three/four/five"
    if result.reason != "return" or result.value != len(expected) or machine.read_cstring(output) != expected:
        fail("variadic register/stack arguments were not marshaled natively")
exercise("x86")
exercise("amd64")
`)
}

func TestVersionQueryNativePointer(t *testing.T) {
	thread, predeclared, err := newStarlarkRuntime("-")
	if err != nil {
		t.Fatal(err)
	}
	predeclared["image"] = syntheticRegistryClientPE(t)
	_, err = starlark.ExecFile(thread, "version-native.star", `
load("@stdlib//windows/selfreg:win32.star", "version_plugin")
def exercise(architecture):
    machine = emulator.machine(architecture=architecture,code=b"\xc3")
    api = version_plugin(binary.concat([image]))
    machine.use(api)
    resource = binary.builder()
    resource.u16le(44)
    resource.u16le(4)
    resource.u16le(0)
    resource.append(binary.encode("VS_VERSION_INFO",encoding="utf16le",nul=True))
    resource.reserve(2)
    resource.u32le(0xfeef04bd)
    data = resource.bytes()
    block = machine.allocate(value=data)
    api.state["blocks"][block] = data
    for name,encoding in [("VerQueryValueA","ascii"),("VerQueryValueW","utf16le")]:
        query = machine.allocate(value=binary.encode("\\",encoding=encoding,nul=True))
        output = machine.allocate(value=b"\xaa"*(machine.pointer_size+4))
        length = machine.allocate(value=b"\xaa"*8)
        result = machine.call(machine.resolve_export("version.dll",name=name),args=[block,query,output,length])
        if result.reason != "return" or result.value != 1 or machine.read_pointer(output) != block+40:
            fail("version query truncated native result pointer")
        if machine.read_u32le(length) != 4 or machine.read(length+4,4) != b"\xaa"*4 or machine.read(output+machine.pointer_size,4) != b"\xaa"*4:
            fail("version query overwrote pointer/length guards")
exercise("x86")
exercise("amd64")
`, predeclared)
	if err != nil {
		if evaluation, ok := err.(*starlark.EvalError); ok {
			t.Fatal(evaluation.Backtrace())
		}
		t.Fatal(err)
	}
}

func TestCRTNativeVAList(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:win32.star", "msvcrt_plugin")
def exercise(architecture):
    machine = emulator.machine(architecture=architecture,code=b"\xc3")
    machine.use(msvcrt_plugin())
    first = machine.allocate(value=binary.encode("alpha",encoding="utf16le",nul=True))
    last = machine.allocate(value=binary.encode("omega",encoding="utf16le",nul=True))
    format = machine.allocate(value=binary.encode("%s %d %I64X %s",encoding="utf16le",nul=True))
    values = [first,0xffffffff,0x55667788,0x11223344,last] if architecture == "x86" else [first,0xdeadbeefffffffff,0x1122334455667788,last]
    # Exactly the consumed slots are mapped: reading sixteen words or using
    # DWORD pointer slots on AMD64 must fail this test.
    args = machine.allocate(size=len(values)*machine.pointer_size)
    for index,value in enumerate(values):
        machine.write_pointer(args+index*machine.pointer_size,value)
    output = machine.allocate(size=128)
    result = machine.call(machine.resolve_export("msvcrt.dll",name="_vsnwprintf"),args=[output,64,format,args])
    expected = "alpha -1 1122334455667788 omega"
    if result.reason != "return" or result.value != len(expected) or machine.read_cstring(output,encoding="utf16le") != expected:
        fail("native va_list formatting failed")
exercise("x86")
exercise("amd64")
`)
}

func TestCRTNewHandlerAcrossArchitectures(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:win32.star", "msvcrt_plugin")
def exercise(architecture,name):
    machine = emulator.machine(architecture=architecture,code=b"\xc3")
    machine.use(msvcrt_plugin())
    address = machine.resolve_export("msvcrt.dll",name=name)
    pointer = 0x123456789 if architecture == "amd64" else 0x12345678
    for value,want in [(pointer,0),(0,pointer),(pointer,0),(pointer,pointer)]:
        result = machine.call(address,args=[value])
        if result.reason != "return" or result.value != want:
            fail("new-handler exchange lost native pointer or previous state")
exercise("x86","?_set_new_handler@@YAP6AHI@ZP6AHI@Z@Z")
exercise("amd64","?_set_new_handler@@YAP6AH_K@ZP6AH0@Z@Z")
`)
}

func TestCryptoAPIHandlesAndDerivationAcrossArchitectures(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:crypto.star", "cryptoapi_plugin")
load("@stdlib//windows/selfreg:win32.star", "kernel32_plugin")
def check(condition):
    if not condition:
        fail("CryptoAPI native-width contract failed")
def exercise(architecture):
    machine = emulator.machine(architecture=architecture,code=b"\xc3")
    kernel = kernel32_plugin()
    api = cryptoapi_plugin(kernel=kernel)
    machine.use([kernel,api])
    if architecture == "amd64":
        api.state["next_handle"] = 0x100000005
    def call(name,args):
        result = machine.call(machine.resolve_export("advapi32.dll",name=name),args=args)
        check(result.reason == "return")
        return result.value
    def output():
        return machine.allocate(value=b"\xaa"*(machine.pointer_size+4))
    def handle(address):
        check(machine.read(address+machine.pointer_size,4) == b"\xaa"*4)
        value = machine.read_pointer(address)
        check(value in api.state["providers"] or value in api.state["hashes"] or value in api.state["keys"])
        return value
    provider_output = output()
    check(call("CryptAcquireContextW",[provider_output,0,0,1,0xf0000000]) == 1)
    provider = handle(provider_output)
    hash_output = output()
    check(call("CryptCreateHash",[provider,0x8003,0,0,hash_output]) == 1)
    hashed = handle(hash_output)
    data = machine.allocate(value=b"abc")
    check(call("CryptHashData",[hashed,data,3,0]) == 1)
    key_output = output()
    for flags,error in [(0,0x80090004),(128<<16|4,0x80090009),(136<<16,0x80090004)]:
        check(call("CryptDeriveKey",[provider,0x6801,hashed,flags,key_output]) == 0)
        check(kernel.state["last_error"] == error)
        check(machine.read(key_output,machine.pointer_size+4) == b"\xaa"*(machine.pointer_size+4))
        check(not api.state["hashes"][hashed].get("finalized",False))
    check(call("CryptDeriveKey",[provider,0x6801,hashed,128<<16|1,key_output]) == 1)
    key = handle(key_output)
    check(api.state["keys"][key]["secret"] == binary.decode("900150983cd24fb0d6963f7d28e17f72",encoding="hex"))
    check(api.state["hashes"][hashed]["finalized"])
    check(call("CryptHashData",[hashed,data,3,0]) == 0)
    check(kernel.state["last_error"] == 0x8009000c)
    check(call("CryptDestroyKey",[key]) == 1)
    check(call("CryptDestroyHash",[hashed]) == 1)
    check(call("CryptReleaseContext",[provider,0]) == 1)
    check(not api.state["keys"] and not api.state["hashes"] and not api.state["providers"])
exercise("x86")
exercise("amd64")
`)
}

func TestLegacySHAContextsAcrossArchitectures(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:crypto.star", "cryptoapi_plugin")
def check(condition):
    if not condition:
        fail("legacy SHA context check failed")
def exercise(architecture):
    machine = emulator.machine(architecture=architecture, code=b"\xc3")
    machine.use(cryptoapi_plugin())
    initialize = machine.resolve_export("advapi32.dll",name="A_SHAInit")
    update = machine.resolve_export("advapi32.dll",name="A_SHAUpdate")
    finalize = machine.resolve_export("advapi32.dll",name="A_SHAFinal")
    for length in [0,1,3,55,56,63,64,65,127,128,129,1000]:
        message = b"x" * length
        data = machine.allocate(value=binary.concat([message,b"\x00"]))
        context = machine.allocate(value=b"\xaa"*92)
        output = machine.allocate(size=20)
        check(machine.call(initialize,args=[context]).reason == "return")
        check(machine.read(context,64) == b"\xaa"*64)
        split = min(length,17)
        check(machine.call(update,args=[context,data,split]).reason == "return")
        # A copied guest context must continue independently; an address-keyed
        # host hasher would not satisfy this contract.
        copied = machine.allocate(value=machine.read(context,92))
        for current in [context,copied]:
            check(machine.call(update,args=[current,data+split,length-split]).reason == "return")
            check(machine.call(finalize,args=[current,output]).reason == "return")
            check(machine.read(output,20) == crypto.hash("sha1",message))
            check(machine.read(current,64) == b"\x00"*64)
            check(machine.read_u32le(current+84) == 0 and machine.read_u32le(current+88) == 0)
exercise("x86")
exercise("amd64")
`)
}
