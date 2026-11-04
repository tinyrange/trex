package starlarkfrontend

import "testing"

func TestCRTIntegerFieldScanning(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:win32.star","msvcrt_plugin")
def exercise(arch):
    m=emulator.machine(architecture=arch,code=b"\xc3")
    m.use(msvcrt_plugin())
    for api,encoding in [("swscanf_s","utf16le"),("swscanf","utf16le"),("sscanf","ascii")]:
        fn=m.resolve_export("msvcrt.dll",name=api)
        output=m.allocate(value=b"G"*64)
        def scan(text,format,pointers):
            source=m.allocate(value=binary.encode(text,encoding=encoding,nul=True))
            fmt=m.allocate(value=binary.encode(format,encoding=encoding,nul=True))
            result=m.call(fn,args=[source,fmt]+pointers)
            if result.reason!="return": fail(result.detail)
            return result.value
        r=scan("{E1DE74AD-C368-4104-ADB1-57D00577247A}","{%x-%hx-%hx-%4hx-%4hx%4hx%4hx}",[output,output+4,output+6,output+8,output+10,output+12,output+14])
        if r!=7 or m.read(output,16)!=binary.decode("ad74dee168c30441b1add05777057a24","hex") or m.read(output+16,8)!=b"G"*8: fail("GUID fields/width/vararg ABI/guards")
        m.write(output,b"G"*64)
        r=scan(" 0xA5:-12:123456789abcdef0!"," %x:%ld:%I64x!",[output,output+4,output+8])
        if r!=3 or m.read_u32le(output)!=165 or m.read_u32le(output+4)!=0xfffffff4 or m.read_u64le(output+8)!=0x123456789abcdef0 or m.read(output+16,8)!=b"G"*8: fail("mixed widths/prefix/sign")
        m.write(output,b"G"*64)
        if scan("1-no","%u-%x",[output,output+4])!=1 or m.read_u32le(output)!=1 or m.read(output+4,8)!=b"G"*8: fail("partial matching mutated later destination")
        if scan("", "%u",[output])!=0xffffffff or scan("bad","%u",[output])!=0: fail("EOF versus matching failure")
        if scan("42 7%", "%*u %u%%",[output])!=1 or m.read_u32le(output)!=7: fail("suppression/literal percent")
        if scan(" 7", "x%u",[output])!=0: fail("literal skipped leading whitespace")
exercise("x86")
exercise("amd64")
`)
}
