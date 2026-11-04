package starlarkfrontend

import "testing"

// Large heap objects own pages; small objects deliberately share bounded
// slabs (covered by TestKernelSmallHeapObjectsUseBoundedSlabs). A freed small
// slot is not required to become an unmapped guest address.
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
a=call("HeapAlloc",[heap,8,4088])
check(call("HeapSize",[heap,0,a])==4088)
m.write(a+4080,b"123456\x00\x00")
check(m.call(m.entry,args=[a+4080]).reason=="return")
check(m.call(m.entry,args=[a+4090]).reason=="instruction")
b=call("HeapAlloc",[heap,8,32])
c=call("HeapReAlloc",[heap,8,a,8192])
check(call("HeapSize",[heap,0,c])==8192)
check(m.read(c+4080,8)==b"123456\x00\x00")
check(m.read(c+4088,4104)==b"\x00"*4104)
check(m.call(m.entry,args=[a]).reason=="instruction")
check(m.call(m.entry,args=[b]).reason=="return")
check(call("HeapFree",[heap,0,c])==1)
check(m.call(m.entry,args=[c]).reason=="instruction")
check(m.call(m.entry,args=[b]).reason=="return")
`)
}
