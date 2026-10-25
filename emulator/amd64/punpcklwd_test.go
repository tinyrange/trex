package amd64

import (
	"github.com/tinyrange/trex/emulator/cpu"
	"testing"
)

func TestPUNPCKLWD(t *testing.T) {
	for _, tc := range []struct {
		name, code   string
		self, memory bool
		want         [16]byte
	}{
		{"register", "660f61c1", false, false, [16]byte{1, 2, 33, 34, 3, 4, 35, 36, 5, 6, 37, 38, 7, 8, 39, 40}},
		{"self", "660f61c0", true, false, [16]byte{1, 2, 1, 2, 3, 4, 3, 4, 5, 6, 5, 6, 7, 8, 7, 8}},
		{"memory", "660f6102", false, true, [16]byte{1, 2, 33, 34, 3, 4, 35, 36, 5, 6, 37, 38, 7, 8, 39, 40}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, m := codeMemory(t, tc.code)
			for i := range c.xmm[0] {
				c.xmm[0][i] = byte(i + 1)
				c.xmm[1][i] = byte(i + 33)
			}
			if tc.memory {
				c.registers[2] = 0x200000000
				if err := m.Map(c.registers[2], c.xmm[1][:], cpu.Read); err != nil {
					t.Fatal(err)
				}
			}
			c.flags = flagCarry | flagOverflow
			if _, err := c.Step(m); err != nil {
				t.Fatal(err)
			}
			if c.xmm[0] != tc.want || c.flags != flagCarry|flagOverflow {
				t.Fatalf("xmm0=%x flags=%x", c.xmm[0], c.flags)
			}
		})
	}
}

func TestPUNPCKLWDMemoryFault(t *testing.T) {
	c, m := codeMemory(t, "660f6102")
	c.registers[2] = 0x200000000
	if err := m.Map(c.registers[2], make([]byte, 8), cpu.Read); err != nil {
		t.Fatal(err)
	}
	c.xmm[0] = [16]byte{1, 2, 3, 4}
	before, pc := c.xmm[0], c.PC()
	if _, err := c.Step(m); err == nil {
		t.Fatal("short operand accepted")
	}
	if c.xmm[0] != before || c.PC() != pc {
		t.Fatal("fault changed architectural state")
	}
}
