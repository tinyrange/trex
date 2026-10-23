package starlarkfrontend

import "testing"

func TestExplicitEmptyIPv4AdapterInventory(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/emulation:iphlpapi.star","no_ipv4_adapters_plugin")
def exercise():
    m=emulator.machine(architecture="amd64",code=b"\xc3")
    m.use(no_ipv4_adapters_plugin())
    fn=m.resolve_export("iphlpapi.dll",name="GetAdaptersInfo")
    size=m.allocate(size=4,value=b"\x34\x12\x00\x00")
    buffer=m.allocate(value=b"unchanged")
    for pointer in [0,buffer]:
        result=m.call(fn,args=[pointer,size])
        if result.reason!="return" or result.value!=232 or m.read_u32le(size)!=0x1234 or m.read(buffer,9)!=b"unchanged":
            fail("empty adapter inventory must report no data, not fabricate an adapter")
    if m.call(fn,args=[buffer,0]).value!=87:
        fail("missing required size pointer")
exercise()
`)
}

func TestDisconnectedWinINetSessionLifetime(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:win32.star","kernel32_plugin")
load("@stdlib//windows/emulation:wininet.star","disconnected_wininet_plugin")
def check(ok):
    if not ok:
        fail("WinINet session contract")
def exercise(arch):
    m=emulator.machine(architecture=arch,code=b"\xc3")
    inet=disconnected_wininet_plugin()
    m.use([kernel32_plugin(),inet])
    open=m.resolve_export("wininet.dll",name="InternetOpenW")
    close=m.resolve_export("wininet.dll",name="InternetCloseHandle")
    for flags in [0,0x10000000]:
        result=m.call(open,args=[0,0,0,0,flags])
        check(result.reason=="return" and result.value!=0)
        handle=result.value
        check(inet.state["handles"][handle]["async"]==bool(flags))
        check(m.call(close,args=[handle]).value==1)
        check(m.call(close,args=[handle]).value==0)
        check(m.call(m.resolve_export("kernel32.dll",name="GetLastError")).value==6)
    check(not inet.state["handles"])
    check(m.call(open,args=[0,0,0,0,0x40000000]).reason=="plugin")
exercise("x86")
exercise("amd64")
`)
}
