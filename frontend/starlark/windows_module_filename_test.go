package starlarkfrontend

import "testing"

func TestModuleFilenameHandlesAndBufferBounds(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:win32.star", "kernel32_plugin")
def exercise(arch, major):
    m=emulator.machine(architecture=arch,code=b"\xc3")
    primary="C:\\App\\Main.dll"
    dependency="C:\\Windows\\System32\\NetSetupApi.dll"
    k=kernel32_plugin(primary,version={"major":major},virtual_modules=["dependency.dll","unspecified.dll"],module_paths={"DEPENDENCY.DLL":dependency})
    m.use(k)
    def call(name,args):
        r=m.call(m.resolve_export("kernel32.dll",name=name),args=args)
        if r.reason!="return": fail(name+": "+r.detail)
        return r.value
    module=m.allocate(value=b"dependency.dll\x00")
    handle=call("GetModuleHandleA",[module])
    if not handle: fail("dependency handle missing")
    output=m.allocate(value=b"X"*256)
    for suffix,encoding,unit in [("A","ascii",1),("W","utf16le",2)]:
        for selected,path in [(0,primary),(handle,dependency)]:
            m.write(output,b"X"*256)
            count=call("GetModuleFileName"+suffix,[selected,output,128])
            expected=binary.encode(path,encoding=encoding,nul=True)
            if count!=len(expected)//unit-1 or m.read(output,len(expected))!=expected or m.read(output+len(expected),2)!=b"XX": fail("wrong module filename/length/guard")
        m.write(output,b"X"*256)
        call("SetLastError",[999])
        count=call("GetModuleFileName"+suffix,[handle,output,4])
        expected=binary.encode(dependency[:4] if major==5 else dependency[:3],encoding=encoding,nul=major!=5)
        if count!=4 or m.read(output,4*unit)!=expected or m.read(output+4*unit,4)!=b"XXXX": fail("truncation width/guard")
        if call("GetLastError",[])!=(999 if major==5 else 122): fail("truncation last-error")
        m.write(output,b"X"*256)
        if call("GetModuleFileName"+suffix,[0xdeadbeef,output,128])!=0 or call("GetLastError",[])!=6 or m.read(output,256)!=b"X"*256: fail("invalid module changed output")
        if call("GetModuleFileName"+suffix,[handle,output,0])!=0 or m.read(output,256)!=b"X"*256: fail("zero capacity changed output")
    # A filename fact alone does not admit a DLL or fabricate an HMODULE.
    absent=m.allocate(value=b"absent.dll\x00")
    if call("GetModuleHandleA",[absent])!=0: fail("fabricated module")
exercise("x86",5)
exercise("x86",10)
exercise("amd64",5)
exercise("amd64",10)
`)
}
