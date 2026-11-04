package starlarkfrontend

import "testing"

func TestNativePerformanceCounterClock(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:win32.star", "kernel32_plugin")
def exercise(arch):
    m=emulator.machine(architecture=arch,code=b"\xc3")
    k=kernel32_plugin()
    m.use(k)
    def call(module,name,args):
        r=m.call(m.resolve_export(module,name=name),args=args)
        if r.reason!="return": fail(name+": "+r.detail)
        return r.value
    a=m.allocate(value=b"G"*16)
    b=m.allocate(value=b"G"*16)
    c=m.allocate(size=8)
    call("kernel32.dll","SetLastError",[91])
    if call("ntdll.dll","NtQueryPerformanceCounter",[a,b]): fail("native query")
    before=m.read_u64le(a)
    frequency=m.read_u64le(b)
    if not call("kernel32.dll","QueryPerformanceFrequency",[c]) or m.read_u64le(c)!=frequency: fail("frequency differs")
    if not call("kernel32.dll","QueryPerformanceCounter",[c]) or m.read_u64le(c)!=before: fail("counter differs")
    call("kernel32.dll","Sleep",[17])
    if call("ntdll.dll","ZwQueryPerformanceCounter",[a,0]): fail("optional frequency")
    if m.read_u64le(a)-before != frequency*17//1000: fail("clock did not advance consistently")
    if m.read(a+8,8)!=b"G"*8 or m.read(b+8,8)!=b"G"*8: fail("LARGE_INTEGER guard")
    m.write(b,b"G"*16)
    if call("ntdll.dll","NtQueryPerformanceCounter",[0,b])!=0xc0000005 or m.read(b,16)!=b"G"*16: fail("null mandatory output")
    if call("kernel32.dll","GetLastError",[])!=91: fail("native changed last error")
exercise("x86")
exercise("amd64")
`)
}
