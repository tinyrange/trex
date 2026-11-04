package starlarkfrontend

import "testing"

func TestPrivateCRTErrnoThreadStorage(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:win32.star", "msvcrt_plugin", "kernel32_plugin")
def exercise(arch):
    kernel=kernel32_plugin()
    kernel.state["current_thread"]={"id":8}
    m=emulator.machine(architecture=arch,code=b"\xc3")
    m.use(msvcrt_plugin(kernel))
    private=m.resolve_export("api-ms-win-crt-private-l1-1-0.dll",name="_o__errno")
    public=m.resolve_export("msvcrt.dll",name="_errno")
    def address(fn):
        result=m.call(fn,args=[])
        if result.reason!="return" or not result.value: fail("errno call failed")
        return result.value
    first=address(private)
    if m.read_u32le(first)!=0 or address(public)!=first: fail("private errno has separate or nonzero initial storage")
    m.write_u32le(first,34)
    if address(private)!=first or m.read_u32le(address(public))!=34: fail("errno storage did not persist")
    kernel.state["current_thread"]={"id":9}
    second=address(public)
    if second==first or m.read_u32le(second)!=0 or address(private)!=second: fail("errno is not per-thread")
    m.write_u32le(second,22)
    kernel.state["current_thread"]={"id":8}
    if address(private)!=first or m.read_u32le(first)!=34 or m.read_u32le(second)!=22: fail("thread switch lost errno state")
exercise("x86")
exercise("amd64")
`)
}
