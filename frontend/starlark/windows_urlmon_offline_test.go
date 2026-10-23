package starlarkfrontend

import "testing"

func TestExplicitOfflineURLMonRejectsBinding(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/emulation:urlmon.star","offline_urlmon_plugin")
def check(ok):
    if not ok:
        fail("offline URL binding contract")
def exercise(arch):
    m=emulator.machine(architecture=arch,code=b"\xc3")
    plugin=offline_urlmon_plugin()
    m.use(plugin)
    fn=m.resolve_export("urlmon.dll",name="URLOpenStreamW")
    url=m.allocate(value=binary.encode("https://example.invalid/settings",encoding="utf16le",nul=True))
    r=m.call(fn,args=[0,url,0,0])
    check(r.reason=="return" and r.value==0x800c0004)
    check(len(plugin.state["requests"])==1)
    check(m.call(fn,args=[0,0,0,0]).value==0x80070057)
    check(m.call(fn,args=[0,url,1,0]).value==0x80070057)
    check(len(plugin.state["requests"])==1)
exercise("x86")
exercise("amd64")
`)
}
