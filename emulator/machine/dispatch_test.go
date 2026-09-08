package machine

import (
	"github.com/tinyrange/trex/emulator/amd64"
	"github.com/tinyrange/trex/emulator/cpu"
	"go.starlark.net/starlark"
	"testing"
)

func TestDispatchFilterMembershipAndSnapshot(t *testing.T) {
	m := &Machine{processor: &amd64.CPU{}, memory: cpu.NewAddressSpace(4096)}
	for i := uint64(0); i < 4096; i++ {
		address := uint64(0x7fff00000000) + i*16
		if i%2 == 0 {
			m.addImport(imported{address: address})
		} else {
			m.setHook(address, hook{})
		}
		if !m.mayDispatch(address) {
			t.Fatalf("false negative at %#x", address)
		}
	}
	clone := m.clone()
	const fresh = 0x1234
	if m.mayDispatch(fresh) {
		t.Fatal("test requires a previously clear bit")
	}
	clone.setHook(fresh, hook{name: "new"})
	if !clone.mayDispatch(fresh) || m.mayDispatch(fresh) {
		t.Fatal("filter aliases snapshot")
	}
	clone.setHook(fresh, hook{name: "replacement"})
	if clone.hooks[fresh].name != "replacement" {
		t.Fatal("hook replacement lost")
	}
}

func TestDispatchFilterCollisionUsesExactAddress(t *testing.T) {
	const pc = 0x1000
	const collision = pc ^ 0x10001
	if dispatchBit(pc) != dispatchBit(collision) {
		t.Fatal("test requires collision")
	}
	m := &Machine{processor: &amd64.CPU{}, memory: cpu.NewAddressSpace(4096), limit: 2}
	if err := m.memory.Map(pc, []byte{0x90, 0xf4}, cpu.Read|cpu.Execute); err != nil {
		t.Fatal(err)
	}
	m.processor.SetPC(pc)
	m.setHook(collision, hook{}) // A mistaken match would invoke a nil callback.
	m.addImport(imported{address: collision})
	result, err := m.run(&starlark.Thread{Name: "collision"})
	if err != nil {
		t.Fatal(err)
	}
	reason, _ := result.(starlark.HasAttrs).Attr("reason")
	if reason != starlark.String("halt") {
		t.Fatalf("unexpected stop: %v", result)
	}
}

var dispatchBenchmarkHit bool

func BenchmarkDispatchLookup(b *testing.B) {
	m := &Machine{}
	for i := uint64(0); i < 2048; i++ {
		m.setHook(0x7ffe00000000+i*16, hook{})
		m.addImport(imported{address: 0x7fff00000000 + i*16})
	}
	for _, filtered := range []bool{false, true} {
		name := "maps"
		if filtered {
			name = "filtered"
		}
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				pc := uint64(0x180001000 + (i & 255))
				hit := false
				if !filtered || m.mayDispatch(pc) {
					_, hit = m.hooks[pc]
					if !hit {
						_, hit = m.imports[pc]
					}
				}
				dispatchBenchmarkHit = hit
			}
		})
	}
}
