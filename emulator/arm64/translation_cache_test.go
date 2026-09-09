package arm64

import (
	"encoding/binary"
	"github.com/tinyrange/trex/emulator/cpu"
	"testing"
)

type observingRAM struct {
	cpu.Memory
	reads int
}

func (m *observingRAM) ReadMemory(a uint64, b []byte, access cpu.Access) error {
	m.reads++
	return m.Memory.ReadMemory(a, b, access)
}

func TestTranslationCacheCoherenceAndObservation(t *testing.T) {
	m := cpu.NewAddressSpace(0x10000)
	data := make([]byte, 0x10000)
	binary.LittleEndian.PutUint64(data[0x1000:], 0x2003)
	binary.LittleEndian.PutUint64(data[0x2010:], 0x3003)
	binary.LittleEndian.PutUint64(data[0x3000:], 0x8403) // privileged RW, AF
	if err := m.Map(0, data, cpu.Read|cpu.Write|cpu.Execute); err != nil {
		t.Fatal(err)
	}
	c := &CPU{currentEL: 4}
	c.SetRegister("sctlr_el1", 1)
	c.SetRegister("ttbr0_el1", 0x1000)
	c.SetRegister("tcr_el1", 25)
	check := func(memory cpu.Memory, want uint64) {
		t.Helper()
		pa, err := c.Translate(memory, 0x400080, cpu.Read)
		if err != nil || pa != want {
			t.Fatalf("PA=%x want=%x err=%v", pa, want, err)
		}
	}
	check(m, 0x8080)
	check(m, 0x8080)
	observer := &observingRAM{Memory: m}
	check(observer, 0x8080)
	check(observer, 0x8080)
	if observer.reads != 6 {
		t.Fatalf("table observations lost: %d", observer.reads)
	}
	var descriptor [8]byte
	binary.LittleEndian.PutUint64(descriptor[:], 0x9403)
	if err := m.WriteMemory(0x3000, descriptor[:]); err != nil {
		t.Fatal(err)
	}
	check(m, 0x9080)
	c.SetRegister("current_el", 0)
	if _, err := c.Translate(m, 0x400080, cpu.Read); err == nil {
		t.Fatal("cached privileged mapping used at EL0")
	}
	c.SetRegister("current_el", 4)
	check(m, 0x9080)
	if _, err := m.Protect(0x1000, 8, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Translate(m, 0x400080, cpu.Read); err == nil {
		t.Fatal("cached walk ignored inaccessible descriptor")
	}
	if _, err := m.Protect(0x1000, 8, cpu.Read|cpu.Write); err != nil {
		t.Fatal(err)
	}
	check(m, 0x9080)
	other := m.Clone()
	binary.LittleEndian.PutUint64(descriptor[:], 0xa403)
	if err := other.WriteMemory(0x3000, descriptor[:]); err != nil {
		t.Fatal(err)
	}
	check(other, 0xa080)
	check(m, 0x9080)
	c.SetRegister("ttbr0_el1", 0x5000)
	if _, err := c.Translate(m, 0x400080, cpu.Read); err == nil {
		t.Fatal("TTBR change used cached mapping")
	}
}
