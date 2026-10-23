package amd64

import (
	"encoding/binary"
	"github.com/tinyrange/trex/emulator/cpu"
	"testing"
)

func TestBSF(t *testing.T) {
	for _, tc := range []struct {
		code        string
		input, want uint64
	}{
		{"480fbcc8", 1 << 63, 63}, {"480fbcc8", 0x10001, 0}, {"0fbcc8", 0xffffffff00008000, 15},
		{"660fbcc8", 0xffffffff00008000, 0xaaaaaaaaaaaa000f},
		{"480fbcc8", 0, 0xaaaaaaaaaaaaaaaa}, {"480fbc0a", 1 << 63, 63},
	} {
		c, m := codeMemory(t, tc.code)
		c.registers[0] = tc.input
		c.registers[1] = 0xaaaaaaaaaaaaaaaa
		c.registers[2] = 0x200000003
		var data [8]byte
		binary.LittleEndian.PutUint64(data[:], tc.input)
		if err := m.Map(c.registers[2], data[:], cpu.Read); err != nil {
			t.Fatal(err)
		}
		c.flags = flagCarry | flagZero
		if _, err := c.Step(m); err != nil {
			t.Fatal(err)
		}
		if c.registers[1] != tc.want || (c.flags&flagZero != 0) != (tc.input == 0) {
			t.Fatalf("%s got%x flags%x", tc.code, c.registers[1], c.flags)
		}
	}
	c, m := codeMemory(t, "480fbc0a")
	c.registers[2] = 0x200000003
	c.registers[1] = 42
	c.flags = flagCarry
	pc := c.PC()
	if _, err := c.Step(m); err == nil {
		t.Fatal("expected memory fault")
	}
	if c.registers[1] != 42 || c.flags != flagCarry || c.PC() != pc {
		t.Fatal("fault changed state")
	}
}
