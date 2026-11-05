package starlarkfrontend

import "testing"

func TestNativeIFEOQueryUsesTargetRegistry(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:registry.star", "registry_plugin")
def exercise(arch):
    m=emulator.machine(architecture=arch,code=b"\xc3")
    r=registry_plugin(values=[dict(hive="SOFTWARE",key="/Microsoft/Windows NT/CurrentVersion/Image File Execution Options/example.exe",name="RpcRuntimeConfigFlags",type="REG_DWORD",value=17)])
    m.use(r)
    fn=m.resolve_export("ntdll.dll",name="LdrQueryImageFileExecutionOptions")
    text=binary.encode("C:\\Windows\\EXAMPLE.EXE",encoding="utf16le")
    name=m.allocate(value=text)
    descriptor=m.allocate(size=16)
    m.write_u16le(descriptor,len(text))
    m.write_u16le(descriptor+2,len(text))
    m.write_pointer(descriptor+(8 if arch=="amd64" else 4),name)
    value=m.allocate(value=binary.encode("RpcRuntimeConfigFlags",encoding="utf16le",nul=True))
    absent=m.allocate(value=binary.encode("Absent",encoding="utf16le",nul=True))
    out=m.allocate(value=b"X"*8)
    length=m.allocate(value=b"X"*8)
    result=m.call(fn,args=[descriptor,value,4,out,4,length])
    if result.reason!="return" or result.value or m.read_u32le(out)!=17 or m.read_u32le(length)!=4 or m.read(out+4,4)!=b"XXXX" or m.read(length+4,4)!=b"XXXX": fail("IFEO value/width")
    m.write(out,b"X"*8)
    m.write(length,b"X"*8)
    result=m.call(fn,args=[descriptor,absent,4,out,4,length])
    if result.reason!="return" or result.value!=0xc0000034 or m.read(out,8)!=b"X"*8 or m.read(length,8)!=b"X"*8: fail("IFEO absent atomicity")
    result=m.call(fn,args=[descriptor,value,4,out,3,length])
    if result.reason!="plugin" or m.read(out,8)!=b"X"*8 or m.read(length,8)!=b"X"*8: fail("unsupported IFEO buffer policy")
    if r.patches(): fail("IFEO query wrote registry")
exercise("x86")
exercise("amd64")
`)
}
