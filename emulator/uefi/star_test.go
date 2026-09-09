package uefi

import (
	"crypto/sha256"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
	"io"
	"testing"
)

func TestStarlarkNativeRewriteCheckpoint(t *testing.T) {
	data, err := io.ReadAll(fixture(t, 0x91000400, 0xd65f03c0))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data[0x200:0x208])
	_, err = starlark.ExecFile(&starlark.Thread{Name: "rewrite-test"}, "rewrite.star", `
def native(vm):
    vm.plugin["calls"] += 1
    vm.register("x0",vm.register("x0")+1)
    return vm.register("lr")
def test():
    vm=uefi(image,memory=16<<20,registers={"x0":41})
    vm.plugin["calls"]=0
    vm.rewrite(vm.register("pc"),8,digest,native,name="increment")
    saved=vm.checkpoint()
    result=vm.run(steps=1,timeout=0)
    if vm.register("x0")!=42 or vm.plugin["calls"]!=1:
        fail("native callback failed")
    vm.restore(saved)
    result=vm.run(steps=1,accelerate=False)
    if vm.register("x0")!=42 or vm.plugin["calls"]!=0:
        fail("interpreter or plugin restore failed")
    vm.close()
test()
`, starlark.StringDict{"uefi": starlark.NewBuiltin("uefi", Builtin), "image": &starfile.Bytes{Data: data}, "digest": starlark.Bytes(digest[:])})
	if err != nil {
		t.Fatal(err)
	}
}

func TestStarlarkCheckpointAndInspectionControls(t *testing.T) {
	data, err := io.ReadAll(fixture(t, 0xf9000020, 0x14000000))
	if err != nil {
		t.Fatal(err)
	}
	thread := &starlark.Thread{Name: "uefi-test"}
	_, err = starlark.ExecFile(thread, "probe.star", `
def check(condition, message):
    if not condition:
        fail(message)
def test():
    vm = uefi(image, memory=16<<20, registers={"x0":42,"x1":0x40200000})
    vm.plugin["nested"] = {"values":[1]}
    held = vm.plugin["nested"]["values"]
    saved = vm.checkpoint()
    held.append(2)
    result = vm.run(steps=10, watch=[(0x40200000,8,"w")])
    check(result.reason == "memory_watch", result)
    check(vm.memory(0x40200000,1) == b"*", "write missing")
    vm.restore(saved)
    check(held == [1] and vm.plugin["nested"]["values"] == held, "plugin alias restoration")
    check(vm.memory(0x40200000,1) == b"\x00", "memory restoration")
    vm.register("x0",99)
    vm.restore(saved)
    check(vm.register("x0") == 42, "checkpoint reuse")
    pc = vm.register("pc")
    result = vm.run(stop_pcs=[pc])
    check(result.reason == "address_stop" and result.steps == 0, result)
    check(vm.disassemble(pc)[0].text == "STR X0, [X1]", "disassembly")
    result = vm.run(steps=5,trace=2)
    check(len(result.trace)==2 and result.steps==5, result)
    vm.set_variable("Example","{5B1B31A1-9562-11D2-8E3F-00A0C969723B}",7,b"value")
    vm.close()
test()
`, starlark.StringDict{"uefi": starlark.NewBuiltin("uefi", Builtin), "image": &starfile.Bytes{Data: data}})
	if err != nil {
		t.Fatal(err)
	}
}
