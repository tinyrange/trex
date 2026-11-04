package starlarkfrontend

import "testing"

func TestCRTSecureWideIntConversion(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:win32.star", "msvcrt_plugin")
def exercise(architecture):
    m=emulator.machine(architecture=architecture,code=b"\xc3")
    m.use(msvcrt_plugin())
    fn=m.resolve_export("msvcrt.dll",name="_itow_s")
    errno=m.call(m.resolve_export("msvcrt.dll",name="_errno"),args=[]).value
    output=m.allocate(value=b"G"*128)
    padding=0xdeadbeef00000000 if architecture=="amd64" else 0
    for value,radix,want in [(0,10,"0"),(0x80000000,10,"-2147483648"),(0xffffffff,10,"-1"),(0xffffffff,16,"ffffffff"),(35,36,"z"),(10,2,"1010")]:
        m.write(output,b"G"*128)
        m.write_u32le(errno,71)
        result=m.call(fn,args=[padding|value,output,len(want)+1,padding|radix])
        if result.reason!="return" or result.value or m.read_cstring(output,encoding="utf16le")!=want or m.read(output+2*(len(want)+1),4)!=b"GGGG" or m.read_u32le(errno)!=71:
            fail("secure integer conversion lost signedness, radix, count, errno or guard: "+str(result))
    for radix,capacity,want_errno in [(10,3,34),(1,32,22),(37,32,22)]:
        m.write(output,b"G"*128)
        result=m.call(fn,args=[100,output,capacity,radix])
        if result.reason=="return" or m.read_u32le(errno)!=want_errno or m.read(output,8)!=b"\x00\x00GGGGGG":
            fail("secure conversion fabricated handler return or overran failure clear")
exercise("x86")
exercise("amd64")
`)
}
