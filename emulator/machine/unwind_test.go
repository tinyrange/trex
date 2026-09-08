package machine

import (
	"debug/pe"
	"encoding/binary"
	"testing"

	"github.com/tinyrange/trex/emulator/amd64"
	"github.com/tinyrange/trex/emulator/cpu"
	"github.com/tinyrange/trex/emulator/peimage"
	"go.starlark.net/starlark"
)

func localUnwindFixture(t *testing.T) (*Machine, uint64, uint64) {
	t.Helper()
	const base, stack, frame, hookAddress = 0x180000000, 0x200000000, 0x200000800, 0x7ffe00000000
	image := &peimage.Image{Architecture: cpu.Architecture{Name: "amd64", PointerSize: 8}, Base: base, Data: make([]byte, 1024)}
	image.Directories[pe.IMAGE_DIRECTORY_ENTRY_EXCEPTION] = pe.DataDirectory{VirtualAddress: 0x200, Size: 12}
	for offset, value := range map[int]uint32{0x200: 0x40, 0x204: 0xa0, 0x208: 0x220, 0x224: 0xb0, 0x228: 1, 0x22c: 0x50, 0x230: 0x70, 0x234: 0xc0, 0x238: 0} {
		binary.LittleEndian.PutUint32(image.Data[offset:], value)
	}
	copy(image.Data[0x220:], []byte{0x11, 0, 0, 0})
	copy(image.Data[0xb0:], []byte{0xff, 0x25, 0x4a, 0x02, 0, 0}) // jmp [base+0x300]
	copy(image.Data[0xc0:], []byte{0x48, 0x89, 0x4a, 0x10, 0xc3}) // finally: [frame+16]=abnormal; ret
	copy(image.Data[0x80:], []byte{0xb8, 42, 0, 0, 0, 0x48, 0x83, 0xc4, 0x38, 0xc3})
	m := &Machine{processor: &amd64.CPU{}, memory: cpu.NewAddressSpace(8192), limit: 100, stackLow: stack, stackHigh: stack + 4096, modules: []module{{name: "fixture.dll", image: image}}, imports: map[uint64]imported{1: {iat: base + 0x300, name: "__C_specific_handler"}}, hooks: make(map[uint64]hook)}
	if err := m.memory.Map(base, image.Data, cpu.Read|cpu.Write|cpu.Execute); err != nil {
		t.Fatal(err)
	}
	if err := m.memory.Map(stack, make([]byte, 4096), cpu.Read|cpu.Write); err != nil {
		t.Fatal(err)
	}
	var returnAddress [8]byte
	binary.LittleEndian.PutUint64(returnAddress[:], base+0x61)
	if err := m.memory.WriteMemory(frame-8, returnAddress[:]); err != nil {
		t.Fatal(err)
	}
	m.processor.SetRegister("rsp", frame-8)
	m.processor.SetRegister("rcx", frame)
	m.processor.SetRegister("rdx", base+0x80)
	m.processor.SetPC(hookAddress)
	m.setHook(hookAddress, hook{module: "kernel32.dll", name: "_local_unwind", argc: 2, callback: starlark.NewBuiltin("local", func(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
		return m.controlMethod(thread, "local_unwind", starlark.Tuple{starlark.MakeUint64(frame), starlark.MakeUint64(base + 0x80)}, nil)
	})})
	return m, frame, base
}

func TestLocalUnwindRunsFinallyAndTransfers(t *testing.T) {
	m, frame, base := localUnwindFixture(t)
	inside, err := m.localUnwindHandlers(frame, base+0x65)
	if err != nil || len(inside) != 0 {
		t.Fatalf("inside scope: %v, %v", inside, err)
	}
	m.processor.SetRegister("rbx", 0x1122334455667788)
	result, err := m.run(&starlark.Thread{Name: "native local unwind"})
	if err != nil {
		t.Fatal(err)
	}
	reason, _ := result.(starlark.HasAttrs).Attr("reason")
	value, _ := m.processor.Register("rax")
	if reason != starlark.String("return") || value != 42 {
		detail, _ := result.(starlark.HasAttrs).Attr("detail")
		t.Fatalf("unwind result %v, value %d: %v", reason, value, detail)
	}
	var cleanup [8]byte
	if err := m.memory.ReadMemory(frame+16, cleanup[:], cpu.Read); err != nil || binary.LittleEndian.Uint64(cleanup[:]) != 1 {
		t.Fatal("native termination handler was not called")
	}
	if value, _ := m.processor.Register("rbx"); value != 0x1122334455667788 {
		t.Fatal("termination call lost nonvolatile register")
	}
}

func TestLocalUnwindRejectsUnknownFramesBeforeCleanup(t *testing.T) {
	for _, change := range []func(*Machine){
		func(m *Machine) { m.processor.SetRegister("rsp", 0x200000700) },
		func(m *Machine) { entry := m.imports[1]; entry.name = "unknown_handler"; m.imports[1] = entry },
		func(m *Machine) { m.modules[0].image.Data[0x223] = 5 },
	} {
		m, frame, base := localUnwindFixture(t)
		change(m)
		if _, err := m.localUnwindHandlers(frame, base+0x80); err == nil {
			t.Fatal("accepted unsupported unwind")
		}
		var cleanup [8]byte
		m.memory.ReadMemory(frame+16, cleanup[:], cpu.Read)
		if binary.LittleEndian.Uint64(cleanup[:]) != 0 {
			t.Fatal("failed validation ran cleanup")
		}
	}
}
