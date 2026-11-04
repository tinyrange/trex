package starlarkfrontend

import "testing"

func TestNativeDisableThreadCallouts(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:win32.star", "kernel32_plugin")
def exercise():
    # A live DLL body which traps if incorrectly sent thread notifications.
    image=binary.concat([windows.pe32_executable(b"\xcc", {"entry":0}, [])])
    m=emulator.machine(image=image,image_name="test.dll")
    k=kernel32_plugin()
    m.use(k)
    fn=m.resolve_export("ntdll.dll",name="LdrDisableThreadCalloutsForDll")
    base=[v.base for v in m.modules if v.primary][0]
    for handle in [0,base+1,0x123456]:
        r=m.call(fn,args=[handle])
        if r.reason!="return" or r.value!=0xc0000135 or k.state["thread_callouts_disabled"]:
            fail("invalid DLL handle changed callout policy")
    r=m.call(fn,args=[base])
    if r.reason!="return" or r.value!=0 or not k.state["thread_callouts_disabled"].get(base):
        fail("live module did not acquire the loader flag")
    # Spawn a returning worker: a disabled DLL must never run its trapping entry.
    worker=m.allocate(value=b"\xb8\x2a\x00\x00\x00\xc2\x04\x00",executable=True)
    create=m.resolve_export("kernel32.dll",name="CreateThread")
    r=m.call(create,args=[0,0,worker,0,0,0])
    if r.reason!="return" or not r.value or k.state["threads"][-1]["result"].value!=42:
        fail("disabled callouts did not permit worker execution: "+str((r.reason,r.detail,r.value,k.state["threads"])))
    # A second native DLL with enabled notifications must fail closed rather than
    # silently omit its loader work; it must not create a worker handle.
    m.load_module(image=binary.concat([windows.pe32_executable(b"\xcc", {"entry":0}, [],image_base=0x600000)]),name="enabled.dll")
    count=len(k.state["threads"])
    r=testing.attempt(m.call,args=[create],kwargs={"args":[0,0,worker,0,0,0]})
    if r.ok and r.value.reason=="return" or len(k.state["threads"])!=count:
        fail("unimplemented enabled callouts were silently skipped")
exercise()
`)
}

func TestNativeDisableThreadCalloutsStaticTLS(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:win32.star", "kernel32_plugin")
def exercise():
    section=binary.builder()
    section.append(b"\xcc")
    section.append(b"\x00"*63)
    for word in [0x401060,0x401064,0x401068,0,0,0]: section.u32le(word)
    section.append(b"\x00"*32)
    image=binary.concat([windows.pe32_executable(section.bytes(),{"entry":0},[])])
    raw=binary.builder()
    raw.append(image.bytes())
    tls_directory=binary.read_u32le(image,0x3c)+24+96+9*8
    raw.patch_u32le(tls_directory,0x1040)
    raw.patch_u32le(tls_directory+4,24)
    m=emulator.machine(image=raw.file(),image_name="tls.dll")
    k=kernel32_plugin()
    m.use(k)
    loaded=[v for v in m.modules if v.primary][0]
    if loaded.tls_index!=0x401068: fail("fixture has no static TLS")
    r=m.call(m.resolve_export("ntdll.dll",name="LdrDisableThreadCalloutsForDll"),args=[loaded.base])
    if r.reason!="return" or r.value!=0 or k.state["thread_callouts_disabled"]:
        fail("native static-TLS success must not set DontCallForThreads")
    worker=m.allocate(value=b"\xc2\x04\x00",executable=True)
    create=m.resolve_export("kernel32.dll",name="CreateThread")
    r=testing.attempt(m.call,args=[create],kwargs={"args":[0,0,worker,0,0,0]})
    if r.ok and r.value.reason=="return" or k.state["threads"]:
        fail("static TLS was reused without per-thread loader support")
exercise()
`)
}

func TestNativeOptionalLookupAndOwnedUnicode(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:win32.star", "kernel32_plugin")
load("@stdlib//windows/emulation:abi.star", "counted_string_layout")
def exercise(arch):
    m=emulator.machine(architecture=arch,code=b"\xc3")
    k=kernel32_plugin(virtual_modules=["kernel32.dll"])
    m.use(k)
    layout=counted_string_layout(m.pointer_size)
    create=m.resolve_export("ntdll.dll",name="RtlCreateUnicodeStringFromAsciiz")
    free=m.resolve_export("ntdll.dll",name="RtlFreeUnicodeString")
    lookup=m.resolve_export("ntdll.dll",name="LdrGetDllHandleEx")
    descriptor=m.allocate(value=b"G"*layout["Size"])
    ascii=m.allocate(value=b"absent.dll\x00")
    r=m.call(create,args=[descriptor,ascii])
    buffer=m.read_pointer(descriptor+layout["Buffer"])
    if r.reason!="return" or r.value!=1 or m.read_u16le(descriptor)!=20 or m.read_u16le(descriptor+2)!=22 or m.read_cstring(buffer,encoding="utf16le")!="absent.dll" or buffer not in k.state["local_allocations"]:
        fail("owned ANSI conversion lost native descriptor/ownership")
    output=m.allocate(value=b"G"*m.pointer_size)
    r=m.call(lookup,args=[0,0,0,descriptor,output])
    if r.reason!="return" or r.value!=0xc0000135 or m.read(output,m.pointer_size)!=b"G"*m.pointer_size:
        fail("missing module lookup changed output or returned the wrong status")
    r=m.call(free,args=[descriptor])
    if r.reason!="return" or buffer in k.state["local_allocations"] or m.read_pointer(descriptor+layout["Buffer"])!=0:
        fail("Unicode string release failed")
    present=m.allocate(value=b"kernel32.dll\x00")
    r=m.call(create,args=[descriptor,present])
    r=testing.attempt(m.call,args=[lookup],kwargs={"args":[0,0,0,descriptor,output]})
    if r.ok and r.value.reason=="return" or m.read(output,m.pointer_size)!=b"G"*m.pointer_size:
        fail("found-module lookup invented reference semantics")
    r=m.call(free,args=[descriptor])
    m.write(descriptor,b"G"*layout["Size"])
    non_ascii=m.allocate(value=b"\xe9\x00")
    r=testing.attempt(m.call,args=[create],kwargs={"args":[descriptor,non_ascii]})
    if r.ok and r.value.reason=="return" or m.read(descriptor,layout["Size"])!=b"G"*layout["Size"]:
        fail("ANSI conversion invented NLS or wrote a partial descriptor")
exercise("x86")
exercise("amd64")
`)
}
