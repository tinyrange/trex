package amd64

import (
	"github.com/tinyrange/trex/emulator/cpu"
	"testing"
)

func TestUnpackHighPackedDouble(t *testing.T) {
	for _, tc := range []struct {
		name, code string
		dst, src   int
		memory     bool
	}{
		{"self", "66 0f 15 d2", 2, 2, false},
		{"distinct", "66 0f 15 c1", 0, 1, false},
		{"extended", "66 45 0f 15 f7", 14, 15, false},
		{"memory", "66 0f 15 02", 0, 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, m := codeMemory(t, tc.code)
			c.xmm[tc.src] = [16]byte{32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47}
			c.xmm[tc.dst] = [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
			source := c.xmm[tc.src]
			if tc.memory {
				c.registers[2] = 0x200000000
				if err := m.Map(c.registers[2], source[:], cpu.Read); err != nil {
					t.Fatal(err)
				}
			}
			c.flags = flagCarry | flagZero | flagOverflow | flagDirection
			before := *c
			want := [16]byte{8, 9, 10, 11, 12, 13, 14, 15, 40, 41, 42, 43, 44, 45, 46, 47}
			if tc.dst == tc.src {
				want = [16]byte{8, 9, 10, 11, 12, 13, 14, 15, 8, 9, 10, 11, 12, 13, 14, 15}
			}
			if _, err := c.Step(m); err != nil {
				t.Fatal(err)
			}
			if c.xmm[tc.dst] != want {
				t.Fatalf("got %x want %x", c.xmm[tc.dst], want)
			}
			if c.flags != before.flags || c.registers != before.registers {
				t.Fatal("changed flags or general registers")
			}
			for i := range c.xmm {
				if i != tc.dst && c.xmm[i] != before.xmm[i] {
					t.Fatalf("changed X%d", i)
				}
			}
		})
	}
}

func TestUnpackHighPackedDoubleFaultAtomicity(t *testing.T) {
	for _, tc := range []struct {
		name   string
		size   int
		offset uint64
		access cpu.Access
	}{
		{"short", 8, 0, cpu.Read},
		{"unaligned", 16, 1, cpu.Read},
		{"unreadable", 16, 0, cpu.Write},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, m := codeMemory(t, "66 0f 15 02")
			c.registers[2] = 0x200000000 + tc.offset
			if err := m.Map(c.registers[2], make([]byte, tc.size), tc.access); err != nil {
				t.Fatal(err)
			}
			c.xmm[0] = [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9}
			c.flags = flagCarry | flagZero | flagOverflow
			before := *c
			if _, err := c.Step(m); err == nil {
				t.Fatal("invalid memory operand succeeded")
			}
			if c.PC() != before.PC() || c.xmm != before.xmm || c.registers != before.registers || c.flags != before.flags {
				t.Fatal("fault changed architectural state")
			}
		})
	}
}
