package starlarkfrontend

import "testing"

func TestNativeRegistryUnknownTypeRoundTrip(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:registry.star", "registry_plugin")
def exercise(architecture):
    m=emulator.machine(architecture=architecture,code=b"\xc3")
    registry=registry_plugin()
    m.use(registry)
    path=m.allocate(value=b"Software\\PropertyTest\x00")
    out=m.allocate(size=m.pointer_size)
    result=m.call(m.resolve_export("advapi32.dll",name="RegCreateKeyExA"),args=[0x80000002,path,0,0,0,0x2001f,0,out,0])
    if result.reason!="return" or result.value: fail("fixture key creation stopped")
    handle=m.read_pointer(out)
    name=m.allocate(size=16 if architecture=="amd64" else 8)
    raw=b"w\x00v\x00i\x00d\x00.\x00i\x00n\x00f\x00\x00\x00\x00\x00"
    data=m.allocate(value=raw)
    padding=0xdeadbeef00000000 if architecture=="amd64" else 0
    result=m.call(m.resolve_export("ntdll.dll",name="NtSetValueKey"),args=[handle,name,0,padding|0xffff2012,data,padding|len(raw)])
    if result.reason!="return" or result.value: fail("unknown numeric native value stopped")
    effects=registry.effects()["values"]
    if len(effects)!=1 or effects[0]["type"]!=0xffff2012 or effects[0]["value"]!=raw:
        fail("native type or uninterpreted bytes changed in captured effects")
    encoded=windows.hive_from_patches("SOFTWARE",[dict(key="/PropertyTest",name="",type=effects[0]["type"],value=effects[0]["value"])])
    value=windows.hive(encoded).find("/PropertyTest").value_records["(default)"]
    if value.type!=0xffff2012 or value.raw!=raw: fail("hive writer changed native property")
    buffer=m.allocate(value=b"G"*64)
    needed=m.allocate(value=b"G"*8)
    result=m.call(m.resolve_export("ntdll.dll",name="NtQueryValueKey"),args=[handle,name,2,buffer,64,needed])
    if result.reason!="return" or result.value or m.read_u32le(buffer+4)!=0xffff2012 or m.read(buffer+12,len(raw))!=raw or m.read(needed+4,4)!=b"GGGG":
        fail("native query lost numeric type, data, or output guard")
    closed=m.call(m.resolve_export("advapi32.dll",name="RegCloseKey"),args=[handle])
    before=registry.effects()
    result=m.call(m.resolve_export("ntdll.dll",name="NtSetValueKey"),args=[handle,0,0,0xffff2012,0,0])
    if result.reason!="return" or result.value!=0xc0000008 or registry.effects()!=before:
        fail("closed handle changed raw property state")
exercise("x86")
exercise("amd64")
`)
}
