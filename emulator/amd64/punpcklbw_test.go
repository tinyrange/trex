package amd64

import (
	"github.com/tinyrange/trex/emulator/cpu"
	"testing"
)

func TestPUNPCKLBW(t *testing.T) {
	for _, tc := range []struct {
		name, code string
		dst, src   int
		memory     bool
		want       [16]byte
	}{
		{"register", "660f60c1", 0, 1, false, [16]byte{1, 33, 2, 34, 3, 35, 4, 36, 5, 37, 6, 38, 7, 39, 8, 40}},
		{"self", "660f60c0", 0, 0, false, [16]byte{1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8}},
		{"extended", "66450f60fe", 15, 14, false, [16]byte{1, 33, 2, 34, 3, 35, 4, 36, 5, 37, 6, 38, 7, 39, 8, 40}},
		{"memory", "660f6002", 0, 1, true, [16]byte{1, 33, 2, 34, 3, 35, 4, 36, 5, 37, 6, 38, 7, 39, 8, 40}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, m := codeMemory(t, tc.code)
			for i := 0; i < 16; i++ {
				c.xmm[tc.src][i] = byte(i + 33)
				c.xmm[tc.dst][i] = byte(i + 1)
			}
			source := c.xmm[tc.src]
			if tc.memory {
				c.registers[2] = 0x200000000
				if err := m.Map(c.registers[2], source[:], cpu.Read); err != nil {
					t.Fatal(err)
				}
			}
			c.flags = flagCarry | flagOverflow
			if _, err := c.Step(m); err != nil {
				t.Fatal(err)
			}
			if c.xmm[tc.dst] != tc.want || c.flags != flagCarry|flagOverflow {
				t.Fatalf("result %x flags %x", c.xmm[tc.dst], c.flags)
			}
			if tc.src != tc.dst && c.xmm[tc.src] != source {
				t.Fatal("source clobbered")
			}
		})
	}
}

func TestPUNPCKLBWFaultPreservesState(t *testing.T) {
	c, m := codeMemory(t, "660f6002")
	c.registers[2] = 0x200000000
	if err := m.Map(c.registers[2], make([]byte, 8), cpu.Read); err != nil {
		t.Fatal(err)
	}
	c.xmm[0] = [16]byte{1, 2, 3, 4}
	c.flags = flagCarry | flagOverflow
	before, pc := c.xmm[0], c.PC()
	if _, err := c.Step(m); err == nil {
		t.Fatal("accepted short memory operand")
	}
	if c.xmm[0] != before || c.PC() != pc || c.flags != flagCarry|flagOverflow {
		t.Fatal("fault changed state")
	}
}
