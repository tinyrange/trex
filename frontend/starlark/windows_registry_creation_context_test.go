package starlarkfrontend

import "testing"

func TestRegistryCreationParentContext(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:registry.star", "registry_plugin")
load("@stdlib//windows/selfreg:win32.star", "kernel32_plugin")
load("@stdlib//windows/selfreg:transactions.star", "registry_transactions_plugin")
def exercise(arch):
    original=windows.compile_sddl("O:SYG:SYD:(A;CI;KA;;;SY)")
    child=windows.compile_sddl("O:BAG:SYD:(A;CI;KR;;;SY)")
    source=windows.hive(windows.hive_from_patches("SOFTWARE",[],keys=[dict(key="/",security=original),dict(key="/Parent",security=original)]))
    state=dict(requests=[],reject=False)
    def create(machine,request):
        state["requests"].append(request)
        if state["reject"]: fail("intentional policy rejection")
        return {key:child for key in request["missing_keys"]}
    r=registry_plugin(hives={"SOFTWARE":source},on_create_key=create)
    k=kernel32_plugin()
    tx=registry_transactions_plugin(r,k)
    m=emulator.machine(architecture=arch,code=b"\xc3")
    def install(machine): pass
    m.use([r,k,tx,emulator.plugin(install,name="creation.observer",state=state)])
    def call(module,name,args):
        result=m.call(m.resolve_export(module,name=name),args=args)
        if result.reason!="return" or result.value: fail(name+": "+str(result.value)+" "+result.detail)
    def wide(text): return m.allocate(value=binary.encode(text,encoding="utf16le",nul=True))
    root=0x80000002
    out=m.allocate(size=m.pointer_size)
    call("ntdll.dll","NtCreateTransaction",[out,0x1f003f,0,0,0,1,0,0,0,0])
    owner=m.read_pointer(out)
    def create_tx(path):
        call("advapi32.dll","RegCreateKeyTransactedW",[root,wide(path),0,0,0,0x2001f,0,out,0,owner,0])
    create_tx("Parent\\A")
    if state["requests"][-1]["parent_key"]!="/Parent" or state["requests"][-1]["parent_security"]!=original: fail("source parent descriptor")
    create_tx("Parent\\A\\B")
    if state["requests"][-1]["parent_key"]!="/Parent/A" or state["requests"][-1]["parent_security"]!=child: fail("transacted parent descriptor")
    call("ntdll.dll","NtRollbackTransaction",[owner,1])
    if r.effects()["keys"]: fail("private security escaped rollback")
    call("advapi32.dll","RegCreateKeyExW",[root,wide("Parent\\A\\B"),0,0,0,0x2001f,0,out,0])
    request=state["requests"][-1]
    if request["parent_key"]!="/Parent" or request["parent_security"]!=original or request["missing_keys"]!=["/Parent/A","/Parent/A/B"]: fail("rollback retained private parent")
    # A policy rejection cannot publish even its intermediate parent.
    before=r.effects()
    state["reject"]=True
    result=m.call(m.resolve_export("advapi32.dll",name="RegCreateKeyExW"),args=[root,wide("Parent\\Rejected\\Child"),0,0,0,0x2001f,0,out,0])
    if result.reason!="plugin" or r.effects()!=before: fail("rejected policy published partial keys")
exercise("x86")
exercise("amd64")
`)
}
