package starlarkfrontend

import "testing"

func TestSIDStringNativeWidthRoundTrip(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:win32.star","kernel32_plugin","security_plugin")
def check(ok):
    if not ok:
        fail("SID string native width/ownership")
def exercise(arch):
    m=emulator.machine(architecture=arch,code=b"\xc3")
    k=kernel32_plugin()
    m.use([k,security_plugin(kernel=k)])
    def call(name,args,dll="advapi32.dll"):
        r=m.call(m.resolve_export(dll,name=name),args=args)
        check(r.reason=="return")
        return r.value
    for suffix,encoding in [("A","ascii"),("W","utf16le")]:
        value="S-1-5-32-544"
        text=m.allocate(value=binary.encode(value,encoding=encoding,nul=True))
        out=m.allocate(value=b"\xaa"*(m.pointer_size+4))
        check(call("ConvertStringSidToSid"+suffix,[text,out])==1)
        sid=m.read_pointer(out)
        check(m.read(out+m.pointer_size,4)==b"\xaa"*4)
        check(call("GetLengthSid",[sid])==16)
        check(call("ConvertSidToStringSid"+suffix,[sid,out])==1)
        string=m.read_pointer(out)
        check(m.read(out+m.pointer_size,4)==b"\xaa"*4)
        check(m.read_cstring(string,encoding=encoding)==value)
        check(call("LocalFree",[string],"kernel32.dll")==0)
        check(call("LocalFree",[sid],"kernel32.dll")==0)
exercise("x86")
exercise("amd64")
`)
}
