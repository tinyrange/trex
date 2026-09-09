package arm64

import (
	"encoding/binary"
	"testing"

	"github.com/tinyrange/trex/emulator/cpu"
)

// Exercise instruction fetch, a load, and a store through the same identity
// block mapping used during UEFI entry. Keep this independent of Windows media.
func BenchmarkTranslatedLoop(b *testing.B) {
	m := cpu.NewAddressSpace(0x10000)
	data := make([]byte, 0x10000)
	binary.LittleEndian.PutUint64(data[0x1000:], 0x2003)
	binary.LittleEndian.PutUint64(data[0x2000:], 0x701)
	for j, op := range []uint32{0xf9400020, 0x91000400, 0xf9000020, 0x17fffffd} {
		binary.LittleEndian.PutUint32(data[0x4000+j*4:], op)
	}
	if err := m.Map(0, data, cpu.Read|cpu.Write|cpu.Execute); err != nil {
		b.Fatal(err)
	}
	c := &CPU{currentEL: 4, pc: 0x4000}
	c.x[1] = 0x8000
	c.SetRegister("sctlr_el1", 1)
	c.SetRegister("ttbr0_el1", 0x1000)
	c.SetRegister("tcr_el1", 25)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := c.Step(m); err != nil {
			b.Fatal(err)
		}
	}
}
