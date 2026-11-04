package starlarkfrontend

import "testing"

func TestCRTBoundedWideLengthCountsCodeUnits(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:win32.star", "msvcrt_plugin")
def exercise(architecture):
    m=emulator.machine(architecture=architecture,code=b"\xc3")
    m.use(msvcrt_plugin())
    fn=m.resolve_export("msvcrt.dll",name="wcsnlen")
    errno=m.call(m.resolve_export("msvcrt.dll",name="_errno"),args=[]).value
    m.write_u32le(errno,71)
    page=m.allocate(size=4096)
    # Surrogate pair ends at the last mapped byte: count WCHARs, do not
    # decode text or read a terminator beyond the caller's bounded slice.
    m.write(page+4092,b"\x3d\xd8\x00\xde")
    for address,maximum,want in [(0,0,0),(page+4092,1,1),(page+4092,2,2),(page+4094,1,1)]:
        result=m.call(fn,args=[address,maximum])
        if result.reason!="return" or result.value!=want or m.read_u32le(errno)!=71:
            fail("bounded WCHAR length lost its limit, code units, or errno: "+str(result))
    m.write(page+4092,b"\x3d\xd8\x00\x00")
    result=m.call(fn,args=[page+4092,1024])
    if result.reason!="return" or result.value!=1 or m.read_u32le(errno)!=71:
        fail("wide length read beyond an early NUL or required valid Unicode")
exercise("x86")
exercise("amd64")
`)
}
