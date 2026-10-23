package starlarkfrontend

import "testing"

func TestLocalHeapPageBackingAndLifetime(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:win32.star", "kernel32_plugin", "shell_plugin")
def check(ok):
    if not ok:
        fail("local heap page/lifetime contract")
m = emulator.machine(architecture="amd64",code=b"\xf3\x0f\x6f\x01\xc3")
kernel = kernel32_plugin()
m.use(kernel)
def call(name,args):
    r=m.call(m.resolve_export("kernel32.dll",name=name),args=args)
    check(r.reason=="return")
    return r.value
p=call("LocalAlloc",[0x40,128])
check(p!=0 and call("LocalSize",[p])==128)
m.write(p+100,binary.encode("/thfirstsetup",encoding="utf16le",nul=True))
check(m.read_cstring(p+100,encoding="utf16le")=="/thfirstsetup")
# This is the unaligned SIMD read through the terminating NUL, not a
# request to enlarge the logical buffer or make every address readable.
check(m.call(m.entry,args=[p+116]).reason=="return")
check(m.call(m.entry,args=[p+4090]).reason=="instruction")
q=call("LocalReAlloc",[p,8193,0x40])
check(q!=p and call("LocalSize",[q])==8193)
check(m.read_cstring(q+100,encoding="utf16le")=="/thfirstsetup")
check(m.read(q+128,16)==b"\x00"*16)
check(m.call(m.entry,args=[p]).reason=="instruction")
check(call("LocalFree",[q])==0)
check(m.call(m.entry,args=[q]).reason=="instruction")
check(call("LocalSize",[q])==0)
`)
}
