package starlarkfrontend

import "testing"

func TestDeviceIoControlOrdinaryExternalBackingQuery(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:win32.star", "kernel32_plugin")
def exercise(architecture):
    m=emulator.machine(architecture=architecture,code=b"\xc3")
    kernel=kernel32_plugin(files={r"C:\ordinary.sys":b"logical driver bytes"})
    m.use(kernel)
    path=m.allocate(value=b"C:\\ordinary.sys\x00")
    handle=m.call(m.resolve_export("kernel32.dll",name="CreateFileA"),args=[path,0x80000000,7,0,3,0x80,0]).value
    ioctl=m.resolve_export("kernelbase.dll",name="DeviceIoControl")
    out=m.allocate(value=b"G"*1024)
    returned=m.allocate(value=b"R"*8)
    before=windows.clone_file_entries(kernel.state["paths"])
    padding=0xdeadbeef00000000 if architecture=="amd64" else 0
    result=m.call(ioctl,args=[handle,padding|0x90310,0,padding,out,padding|1024,returned,0])
    if result.reason!="return" or result.value or kernel.state["last_error"]!=342:
        fail("ordinary file was not reported specifically as not externally backed")
    if m.read(out,1024)!=b"G"*1024 or m.read(returned,8)!=binary.encode("\x00"*4+"R"*4,encoding="ascii"):
        fail("failed external-backing query fabricated a provider or overwrote output guards")
    if kernel.state["paths"]!=before or len(kernel.state["file_queries"])!=2:
        fail("read-only external-backing query changed file objects")
    result=m.call(ioctl,args=[handle,0x90310,0,0,out,1024,0,0])
    if result.reason!="return" or result.value or kernel.state["last_error"]!=87:
        fail("synchronous query accepted NULL returned-size pointer")
    m.call(m.resolve_export("kernel32.dll",name="CloseHandle"),args=[handle])
    result=m.call(ioctl,args=[handle,0x90310,0,0,out,1024,returned,0])
    if result.reason!="return" or result.value or kernel.state["last_error"]!=6:
        fail("closed handle retained authority for control query")
    if kernel.state["paths"]!=before: fail("invalid query changed logical file contents")
exercise("x86")
exercise("amd64")
`)
}

func TestDeviceIoControlStopsUnmodeledControls(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:win32.star", "kernel32_plugin")
def exercise(architecture,variant):
    m=emulator.machine(architecture=architecture,code=b"\xc3")
    kernel=kernel32_plugin(files={r"C:\ordinary.sys":b"logical driver bytes"})
    m.use(kernel)
    path=m.allocate(value=b"C:\\ordinary.sys\x00")
    handle=m.call(m.resolve_export("kernel32.dll",name="CreateFileA"),args=[path,0x80000000,7,0,3,0x80,0]).value
    if variant=="reparse": kernel.state["paths"][r"c:\ordinary.sys"]["attributes"]=0x480
    out=m.allocate(value=b"G"*64)
    returned=m.allocate(value=b"R"*8)
    before=windows.clone_file_entries(kernel.state["paths"])
    kernel.state["last_error"]=0x1234
    result=m.call(m.resolve_export("kernel32.dll",name="DeviceIoControl"),args=[handle,0x90314 if variant=="unknown" else 0x90310,0,0,out,64,returned,out if variant=="overlapped" else 0])
    if result.reason!="plugin": fail("unmodeled control was returned as a native result: "+str(result))
    if m.read(out,64)!=b"G"*64 or m.read(returned,8)!=b"R"*8 or kernel.state["last_error"]!=0x1234 or kernel.state["paths"]!=before:
        fail("unsupported control partially changed observable state")
def all_cases():
    for architecture in ["x86","amd64"]:
        for variant in ["unknown","overlapped","reparse"]: exercise(architecture,variant)
all_cases()
`)
}
