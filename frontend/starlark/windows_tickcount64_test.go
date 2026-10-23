package starlarkfrontend

import "testing"

func TestTickCount64SharedClockAndABI(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:win32.star","kernel32_plugin")
def check(ok):
    if not ok:
        fail("tick count ABI")
def exercise(arch):
    m=emulator.machine(architecture=arch,code=b"\xc3")
    k=kernel32_plugin()
    m.use(k)
    k.state["tick_count"]=0xffffffff-4
    sleep=m.resolve_export("kernel32.dll",name="Sleep")
    check(m.call(sleep,args=[10]).reason=="return")
    fn=m.resolve_export("kernel32.dll",name="GetTickCount64")
    r=m.call(fn)
    check(r.reason=="return")
    actual=r.value
    if arch=="x86":
        actual |= m.get_register("edx")<<32
    check(actual==0x100000005)
    check(m.call(m.resolve_export("kernel32.dll",name="GetTickCount")).value==5)
exercise("x86")
exercise("amd64")
`)
}
