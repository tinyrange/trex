package starlarkfrontend

import "testing"

func TestProcessSnapshotNativeLayouts(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:win32.star", "kernel32_plugin")
def check(ok):
    if not ok:
        fail("process snapshot contract")
def exercise(arch):
    m=emulator.machine(architecture=arch,code=b"\xc3")
    k=kernel32_plugin(module_path="C:\\test\\setup.exe")
    m.use(k)
    def call(name,args):
        r=m.call(m.resolve_export("kernel32.dll",name=name),args=args)
        check(r.reason=="return")
        return r.value
    size=568 if arch=="amd64" else 556
    offset=44 if arch=="amd64" else 36
    p=m.allocate(value=b"\xaa"*(size+8))
    handle=call("CreateToolhelp32Snapshot",[2,0])
    m.write_u32le(p,size-1)
    check(call("Process32FirstW",[handle,p])==0 and k.state["last_error"]==24)
    check(m.read(p+4,4)==b"\xaa"*4)
    m.write_u32le(p,size)
    check(call("Process32FirstW",[handle,p])==1)
    check(m.read_u32le(p+8)==call("GetCurrentProcessId",[]))
    check(m.read_cstring(p+offset,encoding="utf16le")=="setup.exe")
    check(m.read(p+size,8)==b"\xaa"*8)
    saved=m.read(p,size)
    check(call("Process32NextW",[handle,p])==0 and k.state["last_error"]==18)
    check(m.read(p,size)==saved)
    check(call("Process32FirstW",[handle,p])==1)
    check(call("CloseHandle",[handle])==1)
    check(call("Process32NextW",[handle,p])==0 and k.state["last_error"]==6)
exercise("x86")
exercise("amd64")
`)
}
