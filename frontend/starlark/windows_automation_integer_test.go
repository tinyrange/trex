package starlarkfrontend

import "testing"

func TestAutomationUnsignedIntegerConversion(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:win32.star", "oleaut_plugin")
def exercise(arch):
    m=emulator.machine(architecture=arch,code=b"\xc3")
    m.use(oleaut_plugin())
    out=m.allocate(value=b"X"*8)
    named=m.resolve_export("oleaut32.dll",name="VarUI4FromStr")
    ordinal=m.resolve_export("oleaut32.dll",ordinal=277)
    for target in [named,ordinal]:
        for text,value,status in [("1",1,0),(" +00042 ",42,0),("4294967295",0xffffffff,0),("-0",0,0),("4294967296",0,0x8002000a),("-1",0,0x8002000a),("",0,0x80020005)]:
            m.write(out,b"X"*8)
            src=m.allocate(value=binary.encode(text,encoding="utf16le",nul=True))
            r=m.call(target,args=[src,0,0,out])
            if r.reason!="return" or r.value!=status: fail("conversion status: "+text+": "+r.detail)
            if not status and m.read_u32le(out)!=value: fail("conversion value")
            if m.read(out+4,4)!=b"XXXX" or status and m.read(out,4)!=b"XXXX": fail("conversion guard/atomicity")
    for text,lcid,flags in [("1.5",0,0),("1",0x407,0),("1",0,1)]:
        m.write(out,b"X"*8)
        src=m.allocate(value=binary.encode(text,encoding="utf16le",nul=True))
        r=m.call(named,args=[src,lcid,flags,out])
        if r.reason!="plugin" or m.read(out,8)!=b"X"*8: fail("unmodeled conversion did not fail closed")
exercise("x86")
exercise("amd64")
`)
}
