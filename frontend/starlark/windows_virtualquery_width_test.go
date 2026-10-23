package starlarkfrontend

import "testing"

func TestVirtualQueryNativePointerWidth(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:win32.star","kernel32_plugin")
def check(ok):
    if not ok:
        fail("VirtualQuery native layout")
def exercise(arch):
    m=emulator.machine(architecture=arch,code=b"\xc3")
    m.use(kernel32_plugin())
    address=m.allocate(size=4096,address=0x123450000 if arch=="amd64" else 0x12345000)
    query=m.resolve_export("kernel32.dll",name="VirtualQuery")
    output=m.allocate(size=64,value=b"\xaa"*64)
    size=48 if arch=="amd64" else 28
    check(m.call(query,args=[address+5,output,size-1]).value==0)
    check(m.read(output,64)==b"\xaa"*64)
    check(m.call(query,args=[address+5,output,size]).value==size)
    check(m.read_pointer(output)==address and m.read_pointer(output+m.pointer_size)==address)
    check(m.read_pointer(output+(24 if arch=="amd64" else 12))==4096)
    check(m.read_u32le(output+(32 if arch=="amd64" else 16))==0x1000)
    check(m.read_u32le(output+size)==0xaaaaaaaa)
exercise("x86")
exercise("amd64")
`)
}
