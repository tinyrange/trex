package starlarkfrontend

import "testing"

func TestPrivateCRTUnsignedConversion(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:win32.star", "msvcrt_plugin")
def exercise(arch):
    m=emulator.machine(architecture=arch,code=b"\xc3")
    m.use(msvcrt_plugin())
    fn=m.resolve_export("api-ms-win-crt-private-l1-1-0.dll",name="_o__wcstoui64")
    errno_fn=m.resolve_export("api-ms-win-crt-private-l1-1-0.dll",name="_o__errno")
    errno=m.call(errno_fn,args=[]).value
    end=m.allocate(size=m.pointer_size)
    maximum=(1<<64)-1
    for text,base,expected,consumed,error in [
        ("  +0x100000001!",0,0x100000001,14,7),
        ("18446744073709551615",10,maximum,20,7),
        ("18446744073709551616z",10,maximum,20,34),
        ("-18446744073709551616!",10,maximum,21,34),
        ("-1",10,maximum,2,7),
        ("-18446744073709551615",10,1,21,7),
        ("0779",0,63,3,7),
        ("0x",0,0,1,7),
        ("  -0xG",16,0,4,7),
        (" +no",10,0,0,7),
        ("zZ!",36,1295,2,7),
        ("12🙂",10,12,2,7),
    ]:
        source=m.allocate(value=binary.encode(text,encoding="utf16le",nul=True))
        m.write_u32le(errno,7)
        r=m.call(fn,args=[source,end,base])
        value=r.value | (m.get_register("edx")<<32 if arch=="x86" else 0)
        if r.reason!="return" or value!=expected or m.read_pointer(end)!=source+consumed*2 or m.read_u32le(errno)!=error:
            fail("unsigned conversion mismatch: %s %s %s %s %s %s"%(text,r.reason,value,m.read_pointer(end)-source,m.read_u32le(errno),r.detail))
    source=m.allocate(value=binary.encode("42",encoding="utf16le",nul=True))
    if m.call(fn,args=[source,0,10]).value!=42: fail("optional end pointer was required")
    for args in [[0,end,10],[source,end,1],[source,end,37],[source,end,0xffffffff]]:
        m.write_pointer(end,123)
        r=testing.attempt(m.call,args=[fn],kwargs={"args":args})
        if r.ok and r.value.reason=="return": fail("invalid-parameter handler invented")
        if m.read_u32le(errno)!=22 or m.read_pointer(end)!=123: fail("invalid-parameter policy corrupted output")
exercise("x86")
exercise("amd64")
`)
}

func TestPrivateCRTUnsignedLongConversion(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:win32.star", "msvcrt_plugin")
def exercise(arch):
    m=emulator.machine(architecture=arch,code=b"\xc3")
    m.use(msvcrt_plugin())
    errno=m.call(m.resolve_export("msvcrt.dll",name="_errno"),args=[]).value
    end=m.allocate(value=b"G"*16)
    for module,api in [("msvcrt.dll","wcstoul"),("api-ms-win-crt-private-l1-1-0.dll","_o_wcstoul")]:
        fn=m.resolve_export(module,name=api)
        for text,base,expected,consumed,error in [
            ("4294967295",10,0xffffffff,10,7),
            ("4294967296!",10,0xffffffff,10,34),
            ("-4294967295",10,1,11,7),
            ("-4294967296",10,0xffffffff,11,34),
            ("-1",10,0xffffffff,2,7),
            (" +0xffffffff!",0,0xffffffff,12,7),
            (" 0x100000000!",16,0xffffffff,12,34),
            ("0779",0,63,3,7),
            (" +0xG",0,0,3,7),
            ("  -no",10,0,0,7),
            ("zZ!",36,1295,2,7),
            ("12🙂",10,12,2,7),
        ]:
            source=m.allocate(value=binary.encode(text,encoding="utf16le",nul=True))
            m.write_u32le(errno,7)
            m.write(end,b"G"*16)
            r=m.call(fn,args=[source,end,base|(0x123400000000 if arch=="amd64" else 0)])
            if r.reason!="return" or r.value!=expected or m.read_pointer(end)!=source+2*consumed or m.read_u32le(errno)!=error: fail("unsigned long conversion: "+text+" "+str(r))
            if m.read(end+m.pointer_size,16-m.pointer_size)!=b"G"*(16-m.pointer_size): fail("end-pointer width")
        source=m.allocate(value=binary.encode("42",encoding="utf16le",nul=True))
        if m.call(fn,args=[source,0,10]).value!=42: fail("optional end pointer")
        for args in [[0,end,10],[source,end,1],[source,end,37]]:
            m.write_pointer(end,123)
            r=testing.attempt(m.call,args=[fn],kwargs={"args":args})
            if r.ok and r.value.reason=="return": fail("invalid parameter silently accepted")
            if m.read_pointer(end)!=123 or m.read_u32le(errno)!=22: fail("invalid parameter effects")
exercise("x86")
exercise("amd64")
`)
}
