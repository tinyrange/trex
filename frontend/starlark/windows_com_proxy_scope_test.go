package starlarkfrontend

import (
	"go.starlark.net/starlark"
	"testing"
)

func TestCOMProxyRegistrationIsProcessLocal(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:win32.star", "ole32_plugin", "com_plugin")
load("@stdlib//windows/selfreg:registry.star", "registry_plugin")
def check(value):
    if not value:
        fail("process-local proxy registration check failed")
def exercise(architecture, legacy):
    machine=emulator.machine(architecture=architecture,code=b"\xc3")
    registry=registry_plugin()
    com=com_plugin(registry) if legacy else ole32_plugin()
    machine.use([registry,com])
    iid=machine.allocate(value=b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff")
    clsid=machine.allocate(value=b"\x10\x20\x30\x40\x50\x60\x70\x80\x90\xa0\xb0\xc0\xd0\xe0\xf0\x01")
    address=machine.resolve_export("ole32.dll",name="CoRegisterPSClsid")
    result=machine.call(address,args=[iid,clsid])
    check(result.reason=="return" and result.value==0)
    check(com.state["proxy_stubs"]=={"{33221100-5544-7766-8899-AABBCCDDEEFF}":"{40302010-6050-8070-90A0-B0C0D0E0F001}"})
    check(registry.patches()==[] and registry.keys()==[])
    check(ole32_plugin().state["proxy_stubs"]=={})
    result=machine.call(address,args=[0,clsid])
    check(result.reason=="return" and result.value==0x80070057)
    check(len(com.state["proxy_stubs"])==1 and registry.patches()==[])
exercise("x86",False)
exercise("x86",True)
exercise("amd64",False)
exercise("amd64",True)
`)
}

func TestRunnerDoesNotPersistCOMProxyOverrides(t *testing.T) {
	thread, globals, err := newStarlarkRuntime("-")
	if err != nil {
		t.Fatal(err)
	}
	globals["image"] = relocatablePE32TestImage(t, 0x200000)
	_, err = starlark.ExecFile(thread, "proxy-scope.star", `
load("@stdlib//windows/emulation:runner.star", "run")
def execute(machine):
    iid=machine.allocate(value=b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff")
    clsid=machine.allocate(value=b"\x10\x20\x30\x40\x50\x60\x70\x80\x90\xa0\xb0\xc0\xd0\xe0\xf0\x01")
    return machine.call(machine.resolve_export("ole32.dll",name="CoRegisterPSClsid"),args=[iid,clsid])
def check():
    initial={"hive":"SOFTWARE","key":"/Classes/Interface/{33221100-5544-7766-8899-AABBCCDDEEFF}/ProxyStubClsid32","name":"(default)","type":"REG_SZ","value":"{11111111-1111-1111-1111-111111111111}"}
    for values in [[],[initial]]:
        result=run(binary.concat([image]),"fixture.dll",registry_values=values,execute=execute)
        if result["result"].reason!="return" or result["result"].value!=0:
            fail("CoRegisterPSClsid failed")
        if result["patches"] or result["registry_keys"] or result["registry_key_deletions"]:
            fail("process-local proxy mapping leaked into persistent registry effects")
check()
`, globals)
	if err != nil {
		t.Fatal(err)
	}
}
