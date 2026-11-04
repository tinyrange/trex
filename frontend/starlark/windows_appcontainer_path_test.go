package starlarkfrontend

import "testing"

func TestNativeNonAppContainerObjectPath(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:win32.star", "kernel32_plugin", "security_plugin")
def exercise(arch):
    m=emulator.machine(architecture=arch,code=b"\xc3")
    k=kernel32_plugin()
    m.use([k,security_plugin(kernel=k)])
    fn=m.resolve_export("ntdll.dll",name="RtlGetAppContainerNamedObjectPath")
    out=m.allocate(value=b"X"*24)
    size=m.pointer_size*2
    for relative in [0,1]:
        m.write(out,b"X"*24)
        r=m.call(fn,args=[0,0,relative,out])
        if r.reason!="return" or r.value or m.read(out,size)!=b"\x00"*size or m.read(out+size,24-size)!=b"X"*(24-size): fail("non-container native empty-string contract")
    m.write(out,b"X"*24)
    r=m.call(fn,args=[0x123456,0,0,out])
    if r.reason!="return" or r.value!=0xc0000008 or m.read(out,24)!=b"X"*24: fail("invalid token changed output")
    r=m.call(fn,args=[0,0,0,0])
    if r.reason!="return" or r.value!=0xc000000d: fail("null output")
    r=m.call(fn,args=[0,out,0,out])
    if r.reason!="plugin" or m.read(out,24)!=b"X"*24: fail("unmodeled container SID accepted")
exercise("x86")
exercise("amd64")
`)
}
