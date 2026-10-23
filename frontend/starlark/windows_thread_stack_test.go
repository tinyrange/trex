package starlarkfrontend

import "testing"

func TestAMD64ThreadStackLimitsAndRestore(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:win32.star","kernel32_plugin")
def check(ok):
    if not ok:
        fail("thread stack context")
m=emulator.machine(architecture="amd64",code=b"\xc3",gs_base=0x700000000)
k=kernel32_plugin()
m.use(k)
teb=m.get_register("gs_base")
parent=m.stack
m.write_pointer(teb+8,parent.high)
m.write_pointer(teb+16,parent.low)
# Return the active TIB stack limit. It must belong to this execution, not
# the parent whose address would make __chkstk probe unmapped memory.
child=m.allocate(value=b"\x65\x48\x8b\x04\x25\x10\x00\x00\x00\xc3",executable=True)
api=m.resolve_export("kernel32.dll",name="CreateThread")
r=m.call(api,args=[0,0,child,0,0,0])
check(r.reason=="return" and r.value!=0)
t=k.state["threads"][-1]
check(t["result"].reason=="return")
check(t["result"].value!=parent.low and t["result"].value!=0)
check(m.read_pointer(teb+8)==parent.high and m.read_pointer(teb+16)==parent.low)
check(m.stack.low==parent.low and m.stack.high==parent.high)
# A fault is also a context boundary, not a reason to leave the child TIB.
bad=m.allocate(value=b"\x48\x31\xc0\x48\x8b\x00\xc3",executable=True)
check(m.call(api,args=[0,0,bad,0,0,0]).reason=="return")
check(k.state["threads"][-1]["result"].reason=="instruction")
check(m.read_pointer(teb+8)==parent.high and m.read_pointer(teb+16)==parent.low)
check(m.stack.low==parent.low and m.stack.high==parent.high)
`)
}
