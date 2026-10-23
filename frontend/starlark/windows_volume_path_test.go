package starlarkfrontend

import "testing"

func TestVolumePathNameWindowsRoots(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:win32.star","kernel32_plugin")
def check(ok):
    if not ok:
        fail("volume path contract")
def exercise(arch):
    m=emulator.machine(architecture=arch,code=b"\xc3")
    k=kernel32_plugin(environment={"CurrentDirectory":"C:\\work"})
    m.use(k)
    api=m.resolve_export("kernel32.dll",name="GetVolumePathNameW")
    out=m.allocate(value=b"\xaa"*128)
    for source,want in [("c:\\nonexistent\\file","C:\\"),("..\\file","C:\\"),("\\\\server\\share\\folder","\\\\server\\share\\")]:
        p=m.allocate(value=binary.encode(source,encoding="utf16le",nul=True))
        data=binary.encode(want,encoding="utf16le",nul=True)
        capacity=len(data)//2
        padding=0x1234567800000000 if arch=="amd64" else 0
        r=m.call(api,args=[p,out,padding|capacity])
        check(r.reason=="return" and r.value==1)
        check(m.read(out,len(data))==data)
        m.write(out,b"\xaa"*128)
        check(m.call(api,args=[p,out,capacity-1]).value==0)
        check(k.state["last_error"]==206 and m.read(out,4)==b"\xaa"*4)
exercise("x86")
exercise("amd64")
`)
}
