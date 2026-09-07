package emulator

import (
	"testing"

	"go.starlark.net/starlark"
)

func TestMachineDispatchAndWin64Hook(t *testing.T) {
	thread := &starlark.Thread{Name: "machine test"}
	_, err := starlark.ExecFile(thread, "machine.star", `
def check(condition):
    if not condition:
        fail("check failed")

x86 = machine(architecture="x86", code=b"\xb8\x07\x00\x00\x00\xc3")
check(x86.architecture == "x86" and x86.pointer_size == 4)
check(x86.call(x86.entry).value == 7)

# sub rsp,28h; mov rax,200000000h; call rax; add rsp,28h; ret
amd64 = machine(architecture="amd64", base=0x180001000, code=b"\x48\x83\xec\x28\x48\xb8\x00\x00\x00\x00\x02\x00\x00\x00\xff\xd0\x48\x83\xc4\x28\xc3")
check(amd64.architecture == "amd64" and amd64.pointer_size == 8)
def hook(event):
    check(event.args == [0x100000001,0x200000002,0x300000003,0x400000004])
    check(event.return_address == 0x180001010)
    return 0x500000005
amd64.hook(hook,address=0x200000000,argc=4)
result = amd64.call(amd64.entry,args=[0x100000001,0x200000002,0x300000003,0x400000004])
check(result.reason == "return" and result.value == 0x500000005)
allocation = amd64.allocate(size=8)
amd64.write_u64le(allocation,0x123456789abcdef0)
check(amd64.read_u64le(allocation) == 0x123456789abcdef0)
def check_slices(architecture):
    loop = machine(architecture=architecture,code=b"\xeb\xfe",instruction_limit=10)
    check(loop.run(instruction_limit=1).steps == 1)
    check(loop.run().steps == 10)
check_slices("x86")
check_slices("amd64")
bounded = machine(architecture="amd64", code=b"\x90\x90\xf4", base=0x180000000)
stopped = bounded.run(until=bounded.entry+1)
check(stopped.reason == "breakpoint" and stopped.steps == 1)
check(bounded.get_register("rip") == bounded.entry+1)
check(bounded.run(until=bounded.entry+1).steps == 0)
check(bounded.run().reason == "halt")
observed = machine(architecture="amd64",code=b"\x90\x90\x90\xf4",base=0x180000000,trace=True,trace_limit=2,profile=True,profile_interval=1,profile_limit=2)
output = observed.run()
check([entry.pc for entry in output.trace] == [observed.entry+2,observed.entry+3])
counts = observed.profile()
check(counts.operations == 4 and counts.samples == 4 and counts.dropped == 2 and counts.tracked == 2)
check([entry.address for entry in counts.entries] == [observed.entry,observed.entry+1])
observed_allocation = observed.allocate(value=b"native")
copied = observed.snapshot()
copied.write(observed_allocation,b"copied")
copied.set_register("rax",123)
check(observed.read(observed_allocation,6) == b"native" and observed.get_register("rax") == 0)
copied.profile(reset=True)
check(copied.profile().operations == 0 and observed.profile().operations == 4)
`, Builtins())
	if err != nil {
		t.Fatal(err)
	}
}
