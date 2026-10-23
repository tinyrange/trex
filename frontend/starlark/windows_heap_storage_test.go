package starlarkfrontend

import "testing"

func TestWindowsHeapStoragePageBoundary(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:win32.star","kernel32_plugin")
def check(ok):
    if not ok:
        fail("heap storage boundary/lifetime")
m=emulator.machine(architecture="amd64",code=b"\xf3\x0f\x6f\x01\xc3")
k=kernel32_plugin()
m.use(k)
def call(name,args):
    r=m.call(m.resolve_export("kernel32.dll",name=name),args=args)
    check(r.reason=="return")
    return r.value
heap=call("GetProcessHeap",[])
a=call("HeapAlloc",[heap,8,56])
check(call("HeapSize",[heap,0,a])==56)
m.write(a+48,b"123456\x00\x00")
check(m.call(m.entry,args=[a+48]).reason=="return")
check(m.call(m.entry,args=[a+4090]).reason=="instruction")
b=call("HeapAlloc",[heap,8,32])
c=call("HeapReAlloc",[heap,8,a,80])
check(call("HeapSize",[heap,0,c])==80)
check(m.read(c+48,8)==b"123456\x00\x00")
check(m.read(c+56,24)==b"\x00"*24)
check(m.call(m.entry,args=[a]).reason=="instruction")
check(m.call(m.entry,args=[b]).reason=="return")
check(call("HeapFree",[heap,0,c])==1)
check(m.call(m.entry,args=[c]).reason=="instruction")
check(m.call(m.entry,args=[b]).reason=="return")
`)
}
