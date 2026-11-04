package starlarkfrontend

import "testing"

func TestCRTSecureWideUnsignedFormatting(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:win32.star", "msvcrt_plugin")
def exercise(architecture, va=False):
    m=emulator.machine(architecture=architecture,code=b"\xc3")
    m.use(msvcrt_plugin())
    function=m.resolve_export("msvcrt.dll",name="vswprintf_s" if va else "swprintf_s")
    def invoke(function,args):
        if va:
            words=binary.builder()
            for value in args[3:]:
                if m.pointer_size==8: words.u64le(value)
                else: words.u32le(value)
            values=m.allocate(value=words.bytes()) if args[3:] else 0
            args=args[:3]+[values]
        return m.call(function,args=args)
    errno=m.call(m.resolve_export("msvcrt.dll",name="_errno"),args=[]).value
    for format,values,want in [("%04lX",[0xdeadbeef00000010 if architecture=="amd64" else 16],"0010"),("literal %% %u",[0xffffffff],"literal % 4294967295"),("%I64X",[0x55667788,0x11223344] if architecture=="x86" else [0x1122334455667788],"1122334455667788"),("",[],"")]:
        fmt=m.allocate(value=binary.encode(format,encoding="utf16le",nul=True))
        output=m.allocate(value=b"G"*128)
        m.write_u32le(errno,71)
        result=invoke(function,args=[output,len(want)+1,fmt]+values)
        if result.reason!="return" or result.value!=len(want) or m.read_cstring(output,encoding="utf16le")!=want or m.read(output+2*(len(want)+1),4)!=b"GGGG" or m.read_u32le(errno)!=71:
            fail("secure wide formatter lost width, vararg slots, capacity, errno or guard: "+str((architecture,format,result.reason,result.detail,result.value,m.read(output,16),m.read_u32le(errno))))
    text=m.allocate(value=binary.encode("en-US ☃ 😀",encoding="utf16le",nul=True))
    for modifier in ["%ls","%ws"]:
        fmt=m.allocate(value=binary.encode(modifier,encoding="utf16le",nul=True))
        output=m.allocate(value=b"G"*64)
        result=invoke(function,args=[output,11,fmt,text])
        if result.reason!="return" or result.value!=10 or m.read_cstring(output,encoding="utf16le")!="en-US ☃ 😀" or m.read(output+22,4)!=b"GGGG":
            fail("explicit wide-string modifier lost UTF-16 capacity or argument width")
    fmt=m.allocate(value=binary.encode("path/%s/%%/%u",encoding="utf16le",nul=True))
    want="path/en-US ☃ 😀/%/42"
    units=len(binary.encode(want,encoding="utf16le"))//2
    output=m.allocate(value=b"G"*128)
    result=invoke(function,args=[output,units+1,fmt,text,42])
    if result.reason!="return" or result.value!=units or m.read_cstring(output,encoding="utf16le")!=want or m.read(output+2*(units+1),4)!=b"GGGG":
        fail("secure wide-string formatting lost UTF-16 count, varargs or guards")
    result=invoke(function,args=[output,units,fmt,text,42])
    if result.reason=="return" or m.read_u16le(output)!=0 or m.read_u32le(errno)!=34:
        fail("secure wide-string capacity boundary was ignored")
    fmt=m.allocate(value=binary.encode("%04lX",encoding="utf16le",nul=True))
    output=m.allocate(value=b"G"*16)
    result=invoke(function,args=[output,4,fmt,16])
    if result.reason=="return" or m.read(output,8)!=b"\x00\x00GGGGGG" or m.read_u32le(errno)!=34:
        fail("secure range error silently returned or truncated output")
    result=invoke(function,args=[output,8,0])
    if result.reason=="return" or m.read_u32le(errno)!=22:
        fail("secure invalid parameter handler was fabricated")
    fmt=m.allocate(value=binary.encode("%s",encoding="utf16le",nul=True))
    m.write(output,b"G"*16)
    result=testing.attempt(invoke,args=[function],kwargs={"args":[output,8,fmt,0]})
    if result.ok and result.value.reason=="return" or m.read(output,16)!=b"G"*16:
        fail("unsupported secure format was accepted or changed output")
exercise("x86")
exercise("amd64")
exercise("x86",True)
exercise("amd64",True)
`)
}
