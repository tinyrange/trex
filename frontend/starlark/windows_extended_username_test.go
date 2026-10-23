package starlarkfrontend

import "testing"

func TestExtendedLocalUserName(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:win32.star","kernel32_plugin","security_plugin")
def check(ok):
    if not ok:
        fail("extended local username contract")
def exercise(architecture):
    m=emulator.machine(architecture=architecture,code=b"\xc3")
    k=kernel32_plugin()
    m.use([k,security_plugin(user_name="A😀",computer_name="NODE",kernel=k)])
    api=m.resolve_export("secur32.dll",name="GetUserNameExW")
    count=m.allocate(value=b"\x00"*4)
    def call(fmt,buffer):
        r=m.call(api,args=[fmt,buffer,count])
        check(r.reason=="return")
        return r.value
    check(call(2,0)==0 and k.state["last_error"]==234)
    size=m.read_u32le(count)
    check(size==9) # NODE + slash + A + surrogate pair + NUL
    output=m.allocate(value=b"\xaa"*(size*2+4))
    m.write_u32le(count,size-1)
    check(call(2,output)==0 and m.read(output,4)==b"\xaa"*4)
    check(m.read_u32le(count)==size)
    check(call(2,output)==1 and m.read_u32le(count)==size-1)
    check(m.read_cstring(output,encoding="utf16le")=="NODE\\A😀")
    check(m.read(output+size*2,4)==b"\xaa"*4)
    check(call(8,output)==0 and k.state["last_error"]==1332)
    check(call(0,output)==0 and k.state["last_error"]==87)
exercise("x86")
exercise("amd64")
`)
}
