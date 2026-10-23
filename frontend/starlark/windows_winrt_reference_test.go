package starlarkfrontend

import "testing"

func TestWinRTBorrowedStringReference(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/emulation:winrt.star","string_reference_plugin")
def check(ok):
    if not ok:
        fail("HSTRING reference contract")
def exercise(arch):
    m=emulator.machine(architecture=arch,code=b"\xc3")
    m.use(string_reference_plugin())
    create=m.resolve_export("api-ms-win-core-winrt-string-l1-1-0.dll",name="WindowsCreateStringReference")
    raw=m.resolve_export("combase.dll",name="WindowsGetStringRawBuffer")
    delete=m.resolve_export("combase.dll",name="WindowsDeleteString")
    text=m.allocate(value=b"A\x00\x00\x00B\x00\x00\x00")
    header=m.allocate(size=32)
    m.write_u32le(header+(24 if arch=="amd64" else 20),0xfeedface)
    out=m.allocate(size=8)
    size=m.allocate(size=4)
    check(m.call(create,args=[text,3,header,out]).value==0)
    handle=m.read_pointer(out)
    check(m.call(raw,args=[handle,size]).value==text and m.read_u32le(size)==3)
    check(m.call(delete,args=[handle]).value==0)
    check(m.read(text,8)==b"A\x00\x00\x00B\x00\x00\x00")
    check(m.call(raw,args=[handle,size]).value==text)
    check(m.read_u32le(header+(24 if arch=="amd64" else 20))==0xfeedface)
    check(m.call(create,args=[0,1,header,out]).value==0x80004003 and m.read_pointer(out)==0)
    check(m.call(create,args=[text,2,header,out]).value==0x80070057 and m.read_pointer(out)==0)
    check(m.call(create,args=[0,0,header,out]).value==0 and m.read_pointer(out)==0)
    empty=m.call(raw,args=[0,size]).value
    check(m.read_u16le(empty)==0 and m.read_u32le(size)==0)
exercise("x86")
exercise("amd64")
`)
}

func TestDisconnectedNetworkInformationLifetime(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/emulation:winrt.star","string_reference_plugin","disconnected_network_information_plugin")
def check(ok):
    if not ok:
        fail("NetworkInformation lifetime contract")
def exercise(arch):
    m=emulator.machine(architecture=arch,code=b"\xc3")
    strings=string_reference_plugin()
    network=disconnected_network_information_plugin(strings)
    m.use([strings,network])
    name="Windows.Networking.Connectivity.NetworkInformation"
    source=m.allocate(value=binary.encode(name,encoding="utf16le",nul=True))
    header=m.allocate(size=24)
    output=m.allocate(size=8)
    create=m.resolve_export("combase.dll",name="WindowsCreateStringReference")
    check(m.call(create,args=[source,len(name),header,output]).value==0)
    hstring=m.read_pointer(output)
    iid=m.allocate(value=b"\x51\xf8\x74\x50\x0d\x95\x65\x41\x9c\x15\x36\x56\x19\x48\x1e\xea")
    activate=m.resolve_export("api-ms-win-core-winrt-l1-1-0.dll",name="RoGetActivationFactory")
    check(m.call(activate,args=[hstring,iid,output]).value==0)
    obj=m.read_pointer(output)
    table=m.read_pointer(obj)
    query=m.read_pointer(table)
    release=m.read_pointer(table+2*m.pointer_size)
    profile=m.read_pointer(table+7*m.pointer_size)
    check(m.call(query,args=[obj,iid,output]).value==0 and m.read_pointer(output)==obj)
    check(m.call(profile,args=[obj,output]).value==0 and m.read_pointer(output)==0)
    check(network.state["queries"]==[{"method":"GetInternetConnectionProfile","profile":None}])
    check(m.call(profile,args=[obj,0]).value==0x80004003)
    # Unsupported methods stop instead of inventing successful network data.
    result=m.call(m.read_pointer(table+6*m.pointer_size),args=[obj,output])
    check(result.reason=="plugin")
    check(m.call(release,args=[obj]).value==1)
    check(m.call(release,args=[obj]).value==0 and not network.state["objects"])
exercise("x86")
exercise("amd64")
`)
}
