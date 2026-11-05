package amd64

import (
	"encoding/binary"
	"fmt"
	"github.com/tinyrange/trex/emulator/cpu"
	"testing"
)

func TestSegmentSelectorReads(t *testing.T) {
	// MOV m16,Sreg preserves the two following bytes and all flags.
	for i, name := range []string{"es", "cs", "ss", "ds", "fs", "gs"} {
		c, m := codeMemory(t, fmt.Sprintf("8c%02x", 1+i*8))
		c.registers[1] = 0x200000
		if err := m.Map(0x200000, []byte{0xa5, 0xa5, 0xa5, 0xa5}, cpu.Read|cpu.Write); err != nil {
			t.Fatal(err)
		}
		if err := c.SetRegister(name, 0xab03+uint64(i)*8); err != nil {
			t.Fatal(err)
		}
		c.flags = 0xad7
		if _, err := c.Step(m); err != nil {
			t.Fatal(err)
		}
		var data [4]byte
		if err := m.ReadMemory(0x200000, data[:], cpu.Read); err != nil {
			t.Fatal(err)
		}
		if binary.LittleEndian.Uint16(data[:2]) != uint16(0xab03+i*8) || data[2] != 0xa5 || data[3] != 0xa5 || c.flags != 0xad7 {
			t.Fatalf("%s: %x", name, data)
		}
		clone := c.Clone().(*CPU)
		if err := c.SetRegister(name, 0); err != nil {
			t.Fatal(err)
		}
		got, err := clone.Register(name)
		if err != nil || got != 0xab03+uint64(i)*8 {
			t.Fatal("clone lost selector")
		}
		if err := c.SetRegister(name, 0x10000); err == nil {
			t.Fatal("wide selector accepted")
		}
	}
}
