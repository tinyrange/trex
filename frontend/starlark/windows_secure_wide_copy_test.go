package starlarkfrontend

import "testing"

func TestSecureWideCopyNativeUnits(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:win32.star", "msvcrt_plugin")
def exercise(arch):
    m=emulator.machine(architecture=arch,code=b"\xc3")
    m.use(msvcrt_plugin())
    fn=m.resolve_export("msvcrt.dll",name="wcscpy_s")
    out=m.allocate(value=b"X"*16)
    # Preserve surrogate pairs and unpaired UTF-16 units, not decoded runes.
    data=b"\x3d\xd8\x00\xde\x00\xd8\x00\x00"
    src=m.allocate(value=data)
    r=m.call(fn,args=[out,4,src])
    if r.reason!="return" or r.value or m.read(out,8)!=data or m.read(out+8,8)!=b"X"*8: fail("wide copy units/guard")
    m.write(out,b"X"*16)
    r=m.call(fn,args=[out,3,src])
    if r.reason!="plugin" or m.read_u16le(out)!=0 or m.read(out+2,14)!=b"X"*14: fail("range failure clearing/guard")
    errno=m.call(m.resolve_export("msvcrt.dll",name="_errno")).value
    if m.read_u32le(errno)!=34: fail("range errno")
    r=m.call(fn,args=[out,4,0])
    if r.reason!="plugin" or m.read_u32le(errno)!=22: fail("invalid source")
    m.write(out,b"X"*16)
    r=m.call(fn,args=[out,0,src])
    if r.reason!="plugin" or m.read(out,16)!=b"X"*16: fail("zero capacity")
exercise("x86")
exercise("amd64")
`)
}
