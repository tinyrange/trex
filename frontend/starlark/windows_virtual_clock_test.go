package starlarkfrontend

import "testing"

func TestWindowsClockAdvancesWithScheduler(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:win32.star","kernel32_plugin")
def check(ok):
    if not ok:
        fail("virtual Windows clocks disagree")
m=emulator.machine(architecture="amd64",code=b"\xc3")
m.use(kernel32_plugin(system_time=946684800))
out=m.allocate(size=16)
def read64(module,name):
    r=m.call(m.resolve_export(module,name=name),args=[out])
    check(r.reason=="return")
    return m.read_u64le(out)
start=read64("kernel32.dll","GetSystemTimeAsFileTime")
check(read64("kernel32.dll","QueryPerformanceCounter")==0)
check(read64("kernel32.dll","QueryPerformanceFrequency")==10000000)
m.call(m.resolve_export("kernel32.dll",name="Sleep"),args=[1250])
check(read64("kernel32.dll","QueryPerformanceCounter")==12500000)
check(read64("kernel32.dll","GetSystemTimeAsFileTime")==start+12500000)
check(read64("ntdll.dll","NtQuerySystemTime")==start+12500000)
m.call(m.resolve_export("kernel32.dll",name="GetSystemTime"),args=[out])
check(m.read_u16le(out+12)==1 and m.read_u16le(out+14)==250)
`)
}

func TestCombinedModuleReleaseExitsThread(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:win32.star","kernel32_plugin")
def check(ok):
    if not ok:
        fail("combined thread exit returned to its caller")
def exercise(arch):
    m=emulator.machine(architecture=arch,code=b"\xc3")
    m.use(kernel32_plugin())
    exit=m.resolve_export("kernel32.dll",name="FreeLibraryAndExitThread")
    b=binary.builder()
    if arch=="amd64":
        b.append(b"\x48\x83\xec\x28\x31\xc9\xba\x2a\x00\x00\x00\x48\xb8")
        b.u64le(exit)
    else:
        b.append(b"\x6a\x2a\x6a\x00\xb8")
        b.u32le(exit)
    b.append(b"\xff\xd0\xcc")
    code=m.allocate(value=b.bytes(),executable=True)
    result=m.call(code)
    check(result.reason=="return" and result.value==42)
exercise("x86")
exercise("amd64")
`)
}
