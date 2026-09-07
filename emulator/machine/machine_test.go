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
		imports:  map[uint64]imported{thunk: {module: "support.dll", name: "Run", address: thunk}},
		provided: make(map[string]uint64),
	}
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
