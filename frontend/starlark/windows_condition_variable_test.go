package starlarkfrontend

import "testing"

func TestAMD64ConditionVariableExclusiveWorkerWait(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:win32.star","kernel32_plugin")
def check(ok):
    if not ok:
        fail("condition-variable synchronization contract")
m=emulator.machine(architecture="amd64",code=b"\xc3")
k=kernel32_plugin()
m.use(k)
lock=m.allocate(size=8)
cv=m.allocate(size=8)
def api(name):
    return m.resolve_export("kernel32.dll",name=name)
def worker(timeout):
    output=m.allocate(size=8)
    b=binary.builder()
    b.append(b"\x48\x83\xec\x28")
    def call(name,args):
        for opcode,value in zip([b"\x48\xb9",b"\x48\xba",b"\x49\xb8",b"\x49\xb9"],args):
            b.append(opcode)
            b.u64le(value)
        b.append(b"\x48\xb8")
        b.u64le(api(name))
        b.append(b"\xff\xd0")
    def store(offset):
        b.append(b"\x49\xbb")
        b.u64le(output+offset)
        b.append(b"\x41\x89\x03")
    call("AcquireSRWLockExclusive",[lock])
    call("SleepConditionVariableSRW",[cv,lock,timeout,0])
    store(0)
    call("GetLastError",[])
    store(4)
    call("ReleaseSRWLockExclusive",[lock])
    b.append(b"\x48\x83\xc4\x28\xc3")
    address=m.allocate(value=b.bytes(),executable=True)
    m.call(api("CreateThread"),args=[0,0,address,0,0,0])
    return output,k.state["threads"][-1]
a,ta=worker(0xffffffff)
c,tc=worker(0xffffffff)
check(ta["state"]=="waiting" and tc["state"]=="waiting")
check(k.state["critical_sections"][lock]["owner"]==None)
# Waking does not let a sleeper return before it can reacquire the lock.
m.call(api("AcquireSRWLockExclusive"),args=[lock])
m.call(api("WakeConditionVariable"),args=[cv])
k.state["pump_threads"](m)
check(ta["state"]=="waiting" and tc["state"]=="waiting")
m.call(api("ReleaseSRWLockExclusive"),args=[lock])
k.state["pump_threads"](m)
check(ta["state"]=="terminated" and tc["state"]=="waiting")
check(m.read_u32le(a)==1 and m.read_u32le(a+4)==0)
m.call(api("WakeAllConditionVariable"),args=[cv])
k.state["pump_threads"](m)
check(tc["state"]=="terminated" and m.read_u32le(c)==1)
# No wake is retained for a subsequent waiter. Timeout still reacquires.
d,td=worker(15)
k.state["pump_threads"](m)
check(td["state"]=="terminated")
check(m.read_u32le(d)==0 and m.read_u32le(d+4)==1460)
check(k.state["critical_sections"][lock]["owner"]==None)
`)
}
