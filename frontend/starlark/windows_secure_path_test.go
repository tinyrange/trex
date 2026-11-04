package starlarkfrontend

import "testing"

func TestCRTSecureWidePathSplit(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:win32.star", "msvcrt_plugin")
def exercise(architecture):
    m=emulator.machine(architecture=architecture,code=b"\xc3")
    m.use(msvcrt_plugin())
    fn=m.resolve_export("msvcrt.dll",name="_wsplitpath_s")
    errno=m.call(m.resolve_export("msvcrt.dll",name="_errno"),args=[]).value
    outputs=[m.allocate(value=b"G"*128) for n in range(4)]
    for path,want in [("C:"+chr(92)+"folder.with.dot"+chr(92)+"name.ext",["C:",chr(92)+"folder.with.dot"+chr(92),"name",".ext"]),("plain",["","","plain",""]),(".dot",["","","",".dot"]),("C:/dir/",["C:","/dir/","",""])]:
        pointer=m.allocate(value=binary.encode(path,encoding="utf16le",nul=True))
        args=[pointer]
        for output,text in zip(outputs,want):
            m.write(output,b"G"*128)
            args.extend([output,len(binary.encode(text,encoding="utf16le"))//2+1])
        m.write_u32le(errno,71)
        result=m.call(fn,args=args)
        if result.reason!="return" or result.value or m.read_u32le(errno)!=71: fail("secure wide path split failed")
        for output,text in zip(outputs,want):
            size=len(binary.encode(text,encoding="utf16le"))+2
            if m.read_cstring(output,encoding="utf16le")!=text or m.read(output+size,4)!=b"GGGG": fail("path split overwrote component guard")
    pointer=m.allocate(value=binary.encode("name.ext",encoding="utf16le",nul=True))
    m.write(outputs[0],b"G"*128)
    result=m.call(fn,args=[pointer,outputs[0],1,0,0,outputs[1],1,0,0])
    if result.reason=="return" or m.read_u32le(errno)!=34 or m.read(outputs[0],8)!=b"\x00\x00GGGGGG": fail("path range handler was fabricated or clear overran")
exercise("x86")
exercise("amd64")
`)
}
