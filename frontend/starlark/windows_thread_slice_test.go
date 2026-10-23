package starlarkfrontend

import "testing"

func TestAMD64ThreadBudgetIsResumable(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:win32.star","kernel32_plugin")
def check(ok):
    if not ok:
        fail("instruction slice was treated as terminal")
m=emulator.machine(architecture="amd64",code=b"\xc3")
k=kernel32_plugin(thread_instruction_limit=10)
m.use(k)
# 40 iterations deliberately require several scheduling slices.
child=m.allocate(value=b"\xb9\x28\x00\x00\x00\xff\xc9\x75\xfc\xb8\x2a\x00\x00\x00\xc3",executable=True)
r=m.call(m.resolve_export("kernel32.dll",name="CreateThread"),args=[0,0,child,0,0,0])
check(r.reason=="return")
t=k.state["threads"][-1]
check(t["state"]=="runnable")
def finish():
    for unused in range(12):
        if t["state"]=="finished":
            break
        k.state["pump_thread_slice"](m)
finish()
check(t["result"].reason=="return" and t["result"].value==42)
check(t["total_steps"]>10)
`)
}
