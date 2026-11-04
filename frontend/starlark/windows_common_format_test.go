package starlarkfrontend

import "testing"

func TestCRTCommonWideFormatting(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:win32.star", "msvcrt_plugin")
def exercise(architecture):
    m=emulator.machine(architecture=architecture,code=b"\xc3")
    m.use(msvcrt_plugin())
    fn=m.resolve_export("api-ms-win-crt-private-l1-1-0.dll",name="_o___stdio_common_vswprintf")
    text=m.allocate(value=binary.encode("name",encoding="ascii",nul=True))
    wide=m.allocate(value=binary.encode("A😀B",encoding="utf16le",nul=True))
    for format,values,want in [("Local/SM0:%lu:%lu:%hs",[4,304,text],"Local/SM0:4:304:name"),("%ls/%I64X/%%",[wide,0x55667788,0x11223344] if architecture=="x86" else [wide,0x1122334455667788],"A😀B/1122334455667788/%"),("%s",[wide],"A😀B")]:
        args=binary.builder()
        for value in values:
            if architecture=="x86": args.u32le(value)
            else: args.u64le(value)
        va=m.allocate(value=args.bytes())
        fmt=m.allocate(value=binary.encode(format,encoding="utf16le",nul=True))
        out=m.allocate(value=b"G"*256)
        count=len(binary.encode(want,encoding="utf16le"))//2
        prefix=[61,0] if architecture=="x86" else [61]
        result=m.call(fn,args=prefix+[out,count+1,fmt,0,va])
        if result.reason!="return" or result.value!=count or m.read_cstring(out,encoding="utf16le")!=want or m.read(out+2*(count+1),4)!=b"GGGG":
            fail("UCRT ABI or WCHAR count mismatch: "+str((architecture,format,result.reason,result.detail,result.value)))
        for options,capacity,locale in [(61,count,0),(63,100,0),(61,100,1),(0x1003d,100,0)]:
            m.write(out,b"G"*256)
            bad_prefix=[options,0] if architecture=="x86" else [options]
            attempted=testing.attempt(m.call,args=[fn],kwargs={"args":bad_prefix+[out,capacity,fmt,locale,va]})
            if attempted.ok and attempted.value.reason=="return" or m.read(out,256)!=b"G"*256:
                fail("unsupported UCRT behavior returned or wrote output")
    unsupported=m.allocate(value=binary.encode("%n",encoding="utf16le",nul=True))
    attempted=testing.attempt(m.call,args=[fn],kwargs={"args":prefix+[out,100,unsupported,0,va]})
    if attempted.ok and attempted.value.reason=="return": fail("unsupported format accepted")
exercise("x86")
exercise("amd64")
`)
}

func TestCRTCommonSecureFormatting(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:win32.star", "msvcrt_plugin")
def exercise(arch):
    m=emulator.machine(architecture=arch,code=b"\xc3")
    m.use(msvcrt_plugin())
    fn=m.resolve_export("api-ms-win-crt-private-l1-1-0.dll",name="_o___stdio_common_vsnprintf_s")
    for fmt,values,want in [("%d/%011i",[0xffffffff,0x80000000],"-1/-2147483648"),("%05d",[0xffffffd6],"-0042"),("%I64d",[0,0x80000000] if arch=="x86" else [0x8000000000000000],"-9223372036854775808"),("%08lx",[0xc0000135],"c0000135"),("id=%020I64u/%%",[0xffffffff,0xffffffff] if arch=="x86" else [0xffffffffffffffff],"id=18446744073709551615/%")]:
        va=binary.builder()
        for value in values:
            if arch=="x86": va.u32le(value)
            else: va.u64le(value)
        args=m.allocate(value=va.bytes())
        format=m.allocate(value=binary.encode(fmt,encoding="ascii",nul=True))
        out=m.allocate(value=b"G"*128)
        prefix=[60,0] if arch=="x86" else [60]
        max_count=(1<<(m.pointer_size*8))-1
        r=m.call(fn,args=prefix+[out,len(want)+1,max_count,format,0,args])
        if r.reason!="return" or r.value!=len(want) or m.read_cstring(out)!=want or m.read(out+len(want)+1,4)!=b"GGGG":
            fail("secure formatting ABI/count/guard mismatch")
        for capacity,count in [(len(want),max_count),(128,len(want)-1)]:
            m.write(out,b"G"*128)
            r=testing.attempt(m.call,args=[fn],kwargs={"args":prefix+[out,capacity,count,format,0,args]})
            if r.ok and r.value.reason=="return" or m.read(out,128)!=b"G"*128: fail("unsupported truncation wrote or returned")
exercise("x86")
exercise("amd64")
`)
}

func TestPrivateCRTNativeAliases(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:win32.star", "msvcrt_plugin")
def exercise(arch):
    m=emulator.machine(architecture=arch,code=b"\xc3")
    m.use(msvcrt_plugin())
    private="api-ms-win-crt-private-l1-1-0.dll"
    def call(module,name,args):
        r=m.call(m.resolve_export(module,name=name),args=args)
        if r.reason!="return": fail(name+" "+r.reason+" "+r.detail)
        return r.value
    wide=m.allocate(value=binary.encode("A😀B",encoding="utf16le",nul=True))
    if call("api-ms-win-crt-string-l1-1-0.dll","wcsnlen",[wide,10])!=4: fail("alias lost UTF16 unit count")
    if call(private,"wcschr",[wide,66])!=wide+6: fail("alias lost UTF16 search address")
    if call(private,"_o_towupper",[97])!=65 or call(private,"_o_towupper",[65535])!=65535: fail("private wide casing failed")
    for unit,mask,want in [(65,0x181,0x181),(97,0x182,0x182),(48,0x184,0x84),(9,0x68,0x68),(33,0x10,0x10),(0,0x20,0x20),(65535,0xffff,0)]:
        if call(private,"_o_iswctype",[unit|0x12340000,mask|0x56780000])!=want: fail("private classification bits/ABI")
    a=m.allocate(value=binary.encode("Hello",encoding="utf16le",nul=True))
    b=m.allocate(value=binary.encode("hELLo",encoding="utf16le",nul=True))
    if call(private,"_o__wcsicmp",[a,b])!=0: fail("private case comparison failed")
    edge=m.allocate(size=4096)
    m.write(edge+4094,binary.u16le(65))
    if call(private,"_o__wcsnicmp",[edge+4094,wide,1])!=0: fail("bounded compare read past one accessible unit")
    if call(private,"_o__wcsnicmp",[0,0,0])!=0: fail("zero count accessed pointers")
    if call(private,"_o__wcsnicmp",[a,b,5])!=0: fail("bounded case fold")
    out=m.allocate(value=b"G"*32)
    if call(private,"_o__itow_s",[0xffffffff,out,16,10])!=0 or m.read_cstring(out,encoding="utf16le")!="-1": fail("private secure integer conversion failed")
    for name,args in [("_o_iswctype",[0xe9,0x100]),("_o_towupper",[0xe9]),("_o__wcsicmp",[wide,b]),("_o__wcsicmp",[0,b]),("_o__wcsnicmp",[wide,wide,2]),("_o__wcsnicmp",[0,b,1])]:
        r=testing.attempt(m.call,args=[m.resolve_export(private,name=name)],kwargs={"args":args})
        if r.ok and r.value.reason=="return": fail("private CRT invented unsupported NLS/parameter policy")
exercise("x86")
exercise("amd64")
`)
}
