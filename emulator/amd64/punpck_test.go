package amd64

import (
	"bytes"
	"github.com/tinyrange/trex/emulator/cpu"
	"testing"
)

func TestPUNPCKLQDQ(t *testing.T) {
	for _, tc := range []struct {
		name, code   string
		memory, self bool
	}{
		{"self", "660f6cc0", false, true},
		{"register", "660f6cc1", false, false},
		{"memory", "660f6c02", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, m := codeMemory(t, tc.code)
			for i := range c.xmm[0] {
				c.xmm[0][i] = byte(i + 1)
				c.xmm[1][i] = byte(i + 33)
			}
			before := c.xmm[0]
			source := c.xmm[1]
			if tc.self {
				source = before
			}
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
			want := append(append([]byte{}, before[:8]...), source[:8]...)
			if !bytes.Equal(c.xmm[0][:], want) || c.flags != flagCarry|flagOverflow {
				t.Fatalf("xmm0=%x flags=%x", c.xmm[0], c.flags)
			}
		})
	}
}

func TestPUNPCKLQDQMemoryFaultPreservesDestination(t *testing.T) {
	for _, size := range []int{8, 16} {
		c, m := codeMemory(t, "660f6c02")
		address := uint64(0x200000000)
		if size == 16 {
			address++
		} // A full, but unaligned operand also faults.
		c.registers[2] = address
		if err := m.Map(address, make([]byte, size), cpu.Read); err != nil {
			t.Fatal(err)
		}
		c.xmm[0] = [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9}
		before, pc := c.xmm[0], c.PC()
		if _, err := c.Step(m); err == nil {
			t.Fatal("invalid memory operand succeeded")
		}
		if c.xmm[0] != before || c.PC() != pc {
			t.Fatal("fault changed architectural state")
		}
	}
}
