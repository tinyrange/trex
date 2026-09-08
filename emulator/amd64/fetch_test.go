package amd64

import (
	"bytes"
	"math"
	"testing"

	"github.com/tinyrange/trex/emulator/cpu"
)

type countedFetchMemory struct {
	*cpu.AddressSpace
	reads int
}

func TestScalarMemoryPaths(t *testing.T) {
	for _, width := range []int{1, 2, 4, 8} {
		space := cpu.NewAddressSpace(32)
		if err := space.Map(0x1000, make([]byte, 16), cpu.Read|cpu.Write); err != nil {
			t.Fatal(err)
		}
		for _, memory := range []cpu.Memory{space, &countedFetchMemory{AddressSpace: space}} {
			if err := writeWord(memory, 0x1001, width, math.MaxUint64); err != nil {
				t.Fatal(err)
			}
			value, err := readWord(memory, 0x1001, width)
			if err != nil || value != math.MaxUint64>>(64-width*8) {
				t.Fatalf("width=%d value=%x error=%v", width, value, err)
			}
			if _, err := readWord(memory, 0x1010, width); err == nil {
				t.Fatal("unmapped scalar read succeeded")
			}
		}
	}
}

func BenchmarkScalarMemory(b *testing.B) {
	space := cpu.NewAddressSpace(32)
	if err := space.Map(0x1000, make([]byte, 16), cpu.Read|cpu.Write); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if err := writeWord(space, 0x1000, 8, 42); err != nil {
			b.Fatal(err)
		}
		if _, err := readWord(space, 0x1000, 8); err != nil {
			b.Fatal(err)
		}
	}
}

func (m *countedFetchMemory) ReadMemory(address uint64, data []byte, access cpu.Access) error {
	m.reads++
	return m.AddressSpace.ReadMemory(address, data, access)
}

func TestFetchUsesSingleRead(t *testing.T) {
	m := &countedFetchMemory{AddressSpace: cpu.NewAddressSpace(4096)}
	if err := m.Map(0x1000, bytes.Repeat([]byte{0x90}, 32), cpu.Execute); err != nil {
		t.Fatal(err)
	}
	c := CPU{rip: 0x1000}
	if _, err := c.Step(m); err != nil {
		t.Fatal(err)
	}
	if m.reads != 1 || c.PC() != 0x1001 {
		t.Fatalf("reads=%d pc=%x", m.reads, c.PC())
	}
}

func TestFetchBoundaryAndChangedCode(t *testing.T) {
	for _, base := range []uint64{0x1000, math.MaxUint64 - 15} {
		m := cpu.NewAddressSpace(4096)
		if err := m.Map(base, bytes.Repeat([]byte{0x90}, 16), cpu.Read|cpu.Write|cpu.Execute); err != nil {
			t.Fatal(err)
		}
		c := CPU{rip: base}
		if _, err := c.Step(m); err != nil {
			t.Fatal(err)
		}
		// Cached NOP must not hide a changed MOV immediate or changed permissions.
		if err := m.WriteMemory(base, []byte{0xb8, 42, 0, 0, 0}); err != nil {
			t.Fatal(err)
		}
		c.SetPC(base)
		if _, err := c.Step(m); err != nil || c.registers[0] != 42 {
			t.Fatalf("modified code: %v", err)
		}
		if _, err := m.Protect(base+5, 11, cpu.Read); err != nil {
			t.Fatal(err)
		}
		c.SetPC(base)
		if _, err := c.Step(m); err != nil || c.PC() != base+5 {
			t.Fatalf("short executable prefix: %v", err)
		}
		if _, err := m.Protect(base, 1, cpu.Read); err != nil {
			t.Fatal(err)
		}
		c.SetPC(base)
		if _, err := c.Step(m); err == nil {
			t.Fatal("cached instruction bypassed protection")
		}
	}
	m := cpu.NewAddressSpace(1)
	if err := m.Map(math.MaxUint64, []byte{0x90}, cpu.Execute); err != nil {
		t.Fatal(err)
	}
	c := CPU{rip: math.MaxUint64}
	if _, err := c.Step(m); err != nil || c.PC() != 0 {
		t.Fatalf("last-address NOP: %v", err)
	}
}

func BenchmarkInstructionStep(b *testing.B) {
	m := cpu.NewAddressSpace(4096 * 256)
	for i := 0; i < 256; i++ {
		if err := m.Map(uint64(0x1000+i*8192), bytes.Repeat([]byte{0x90}, 4096), cpu.Execute); err != nil {
			b.Fatal(err)
		}
	}
	c := CPU{rip: 0x1000}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.SetPC(0x1000)
		if _, err := c.Step(m); err != nil {
			b.Fatal(err)
		}
	}
}
