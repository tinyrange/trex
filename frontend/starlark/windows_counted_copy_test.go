package starlarkfrontend

import "testing"

func TestNativeCountedUnicodeCopyAppendWidths(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:win32.star","kernel32_plugin")
def exercise(arch):
    m=emulator.machine(architecture=arch,code=b"\xc3")
    m.use(kernel32_plugin())
    offset=8 if arch=="amd64" else 4
    def descriptor(pointer,length,maximum):
        p=m.allocate(value=b"\xa5"*(16 if arch=="amd64" else 8))
        m.write_u16le(p,length)
        m.write_u16le(p+2,maximum)
        m.write_pointer(p+offset,pointer)
        return p
    def call(name,args):
        r=m.call(m.resolve_export("ntdll.dll",name=name),args=args)
        if r.reason!="return": fail(name+" failed: "+r.detail)
        return r.value
    # Non-BMP pair and an unpaired surrogate must remain raw UTF-16 units.
    raw=b"A\x00\x3d\xd8\x00\xde\x00\xd8"
    source=m.allocate(value=binary.concat([raw,b"\x00\x00"]).bytes())
    src=descriptor(source,len(raw),len(raw)+2)
    out=m.allocate(value=b"G"*24)
    dst=descriptor(out,0,10)
    call("RtlCopyUnicodeString",[dst,src])
    if m.read_u16le(dst)!=8 or m.read(out,12)!=binary.concat([raw,b"\x00\x00GG"]).bytes(): fail("copy lost native pointer or UTF16 units")
    if arch=="amd64" and m.read(dst+4,4)!=b"\xa5"*4: fail("copy overwrote descriptor padding")
    # Exact fit has no spare terminator; too-small append is atomic.
    m.write_u16le(dst,0)
    m.write_u16le(dst+2,8)
    m.write(out,b"G"*24)
    if call("RtlAppendUnicodeToString",[dst,source])!=0 or m.read(out,10)!=binary.concat([raw,b"GG"]).bytes(): fail("append counted Unicode characters rather than units")
    before=m.read(out,24)
    if call("RtlAppendUnicodeStringToString",[dst,src])!=0xc0000023 or m.read(out,24)!=before or m.read_u16le(dst)!=8: fail("failed append changed data")
    m.write_u16le(dst+2,18)
    if call("RtlAppendUnicodeStringToString",[dst,src])!=0 or m.read(out,20)!=binary.concat([raw,raw,b"\x00\x00GG"]).bytes(): fail("counted append ABI mismatch")
    # Copy truncates at available WCHAR storage and NULL source clears Length.
    m.write_u16le(dst+2,4)
    call("RtlCopyUnicodeString",[dst,src])
    if m.read_u16le(dst)!=4 or m.read(out,4)!=raw[:4]: fail("copy did not truncate")
    call("RtlCopyUnicodeString",[dst,0])
    if m.read_u16le(dst)!=0 or m.read(out,2)!=b"\x00\x00": fail("null-source copy")
exercise("x86")
exercise("amd64")
`)
}
