package machine

import (
	"testing"

	"github.com/tinyrange/trex/emulator/amd64"
	"github.com/tinyrange/trex/emulator/cpu"
	"github.com/tinyrange/trex/emulator/windowsabi"
	"go.starlark.net/starlark"
)

func TestResumeImportAfterProvidingTarget(t *testing.T) {
	const thunk, target, stack = 0x7fff00000000, 0x180001000, 0x200000000
	m := &Machine{
		processor: &amd64.CPU{}, memory: cpu.NewAddressSpace(8192), limit: 20,
		provided: make(map[string]uint64),
	}
	m.addImport(imported{module: "support.dll", name: "Run", address: thunk})
	if err := m.memory.Map(stack, make([]byte, 4096), cpu.Read|cpu.Write); err != nil {
		t.Fatal(err)
	}
	// mov rax,rcx; ret -- retain an argument that exceeds the 32-bit range.
	if err := m.memory.Map(target, []byte{0x48, 0x89, 0xc8, 0xc3}, cpu.Read|cpu.Execute); err != nil {
		t.Fatal(err)
	}
	if err := windowsabi.PrepareAMD64IntegerCall(m.processor, m.memory, thunk, stack+4096, 0, []uint64{0x123456789abcdef0}); err != nil {
		t.Fatal(err)
	}
	thread := &starlark.Thread{Name: "resume import"}
	result, err := m.run(thread)
	if err != nil {
		t.Fatal(err)
	}
	reason, _ := result.(starlark.HasAttrs).Attr("reason")
	if reason != starlark.String("missing-import") || m.processor.PC() != thunk {
		t.Fatalf("initial stop = %v at %#x", reason, m.processor.PC())
	}
	m.provided[exportKey("support.dll", "Run", 0)] = target
	result, err = m.run(thread)
	if err != nil {
		t.Fatal(err)
	}
	reason, _ = result.(starlark.HasAttrs).Attr("reason")
	value, _ := m.processor.Register("rax")
	if reason != starlark.String("return") || value != 0x123456789abcdef0 {
		t.Fatalf("resumed stop = %v, value %#x", reason, value)
	}
}

func TestSpawnExecutionPreservesParentContext(t *testing.T) {
	const target, mainStack, executionStack = 0x180001000, 0x200000000, 0x300000000
	m := &Machine{
		processor: &amd64.CPU{}, memory: cpu.NewAddressSpace(1 << 20), limit: 20,
		memoryLimit: 1 << 20, stackLow: mainStack, stackHigh: mainStack + 0x1000,
		nextAllocation: executionStack, allocationNames: make(map[uint64]string),
	}
	// mov rax,rcx; ret
	if err := m.memory.Map(target, []byte{0x48, 0x89, 0xc8, 0xc3}, cpu.Read|cpu.Execute); err != nil {
		t.Fatal(err)
	}
	if err := m.memory.Map(mainStack, make([]byte, 0x1000), cpu.Read|cpu.Write); err != nil {
		t.Fatal(err)
	}
	m.processor.SetPC(0x123456789)
	if err := m.processor.SetRegister("rax", 0xabcdef); err != nil {
		t.Fatal(err)
	}
	execution, err := m.spawn(target, []uint64{0x123456789abcdef0}, nil)
	if err != nil {
		t.Fatal(err)
	}
	result, err := execution.runBuiltin(&starlark.Thread{Name: "spawn"}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	reason, _ := result.(starlark.HasAttrs).Attr("reason")
	value, _ := result.(starlark.HasAttrs).Attr("value")
	if reason != starlark.String("return") || value.String() != "1311768467463790320" || !execution.done {
		t.Fatalf("execution result reason=%v value=%v done=%t", reason, value, execution.done)
	}
	parentValue, _ := m.processor.Register("rax")
	if m.processor.PC() != 0x123456789 || parentValue != 0xabcdef {
		t.Fatalf("parent context pc=%#x rax=%#x", m.processor.PC(), parentValue)
	}
	if err := m.memory.CheckMemory(executionStack, 1, cpu.Read); err == nil {
		t.Fatal("completed execution retained its stack")
	}
}
