package starlarkfrontend

import "testing"

func TestCreateFileNativeWidthAndDWORDArguments(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:win32.star","kernel32_plugin")
def check(ok):
    if not ok:
        fail("CreateFile ABI contract")
def exercise(arch):
    m=emulator.machine(architecture=arch,code=b"\xc3")
    k=kernel32_plugin()
    m.use(k)
    p=m.allocate(value=binary.encode("C:\\file",encoding="utf16le",nul=True))
    fn=m.resolve_export("kernel32.dll",name="CreateFileW")
    padding=0x1234567800000000 if arch=="amd64" else 0
    invalid=(1<<(m.pointer_size*8))-1
    def call(disposition):
        r=m.call(fn,args=[p,0,3,0,padding|disposition,padding|0x80,0])
        check(r.reason=="return")
        return r.value
    check(call(3)==invalid and k.state["last_error"]==2)
    created=call(1)
    check(created!=invalid and created!=0)
    check(call(1)==invalid and k.state["last_error"]==80)
    check(call(3)!=invalid)
    check(call(99)==invalid and k.state["last_error"]==87)
    check(all([q["flags"]==0x80 for q in k.state["file_queries"]]))
exercise("x86")
exercise("amd64")
`)
}
