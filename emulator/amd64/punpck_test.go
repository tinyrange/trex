package amd64

import (
	"bytes"
	"github.com/tinyrange/trex/emulator/cpu"
	"testing"
)

func TestUnpackLowQuadword(t *testing.T) {
	for _, tc := range []struct {
		name, code   string
		memory, self bool
	}{
		{"integer-self", "660f6cc0", false, true},
		{"integer-register", "660f6cc1", false, false},
		{"integer-memory", "660f6c02", true, false},
		{"double-self", "660f14c0", false, true},
		{"double-register", "660f14c1", false, false},
		{"double-memory", "660f1402", true, false},
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

func TestUnpackLowQuadwordMemoryFaultPreservesDestination(t *testing.T) {
	for _, code := range []string{"660f6c02", "660f1402", "660f6202", "660ffe02"} {
		for _, size := range []int{8, 16} {
			c, m := codeMemory(t, code)
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
}

func TestUnpackLowDoublewords(t *testing.T) {
	for _, tc := range []struct {
		name, code   string
		memory, self bool
	}{
		{"self", "660f62c0", false, true},
		{"register", "660f62c1", false, false},
		{"memory", "660f6202", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, m := codeMemory(t, tc.code)
			c.xmm[0] = [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
			c.xmm[1] = [16]byte{33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48}
			before, source := c.xmm[0], c.xmm[1]
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
			want := append(append(append(append([]byte{}, before[:4]...), source[:4]...), before[4:8]...), source[4:8]...)
			if !bytes.Equal(c.xmm[0][:], want) || c.flags != flagCarry|flagOverflow {
				t.Fatalf("xmm0=%x flags=%x", c.xmm[0], c.flags)
			}
		})
	}
}
