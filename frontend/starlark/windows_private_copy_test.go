package starlarkfrontend

import "testing"

func TestPrivateCRTSecureCopy(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:win32.star", "msvcrt_plugin")
def exercise(arch):
    m=emulator.machine(architecture=arch,code=b"\xc3")
    m.use(msvcrt_plugin())
    fn=m.resolve_export("api-ms-win-crt-private-l1-1-0.dll",name="_o_memcpy_s")
    source=m.allocate(value=b"\x00\xffNATIVE\x00")
    out=m.allocate(value=b"G"*24)
    r=m.call(fn,args=[out+4,16,source,9])
    if r.reason!="return" or r.value!=0 or m.read(out,24)!=binary.concat([b"G"*4,b"\x00\xffNATIVE\x00",b"G"*11]).bytes():
        fail("private secure-copy ABI, bytes, or guard mismatch: %s %s %s %s"%(r.reason,r.value,r.detail,hex(m.read(out,24))))
    r=m.call(fn,args=[0,0,0,0])
    if r.reason!="return" or r.value!=0: fail("zero-count copy accessed a null buffer")
    for args in [[out,7,source,8],[out,24,0,8],[0,24,source,8],[out,24,out+1,8],[out,24,out,8],[out,32<<20,source,32<<20]]:
        m.write(out,b"G"*24)
        r=testing.attempt(m.call,args=[fn],kwargs={"args":args})
        if r.ok and r.value.reason=="return": fail("private secure-copy invented invalid-parameter or overlap policy")
        if m.read(out,24)!=b"G"*24: fail("unsupported copy modified its destination")
exercise("x86")
exercise("amd64")
`)
}
