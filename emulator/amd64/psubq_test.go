package amd64

import (
	"encoding/binary"
	"github.com/tinyrange/trex/emulator/cpu"
	"testing"
)

func TestPSUBQIndependentWrapAndFlags(t *testing.T) {
	for _, tc := range []struct {
		name, code   string
		memory, self bool
	}{
		{"register", "660ffbc1", false, false},
		{"memory", "660ffb02", true, false},
		{"self", "660ffbc0", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, m := codeMemory(t, tc.code)
			binary.LittleEndian.PutUint64(c.xmm[0][:], 0)
			binary.LittleEndian.PutUint64(c.xmm[0][8:], 0x8000000000000000)
			binary.LittleEndian.PutUint64(c.xmm[1][:], 1)
			binary.LittleEndian.PutUint64(c.xmm[1][8:], 1)
			source := c.xmm[1]
			if tc.memory {
				c.registers[2] = 0x200000000
				if err := m.Map(c.registers[2], source[:], cpu.Read); err != nil {
					t.Fatal(err)
				}
			}
			c.flags = flagCarry | flagZero | flagOverflow
			if _, err := c.Step(m); err != nil {
				t.Fatal(err)
			}
			want := [2]uint64{0xffffffffffffffff, 0x7fffffffffffffff}
			if tc.self {
				want = [2]uint64{}
			}
			if binary.LittleEndian.Uint64(c.xmm[0][:]) != want[0] || binary.LittleEndian.Uint64(c.xmm[0][8:]) != want[1] || c.xmm[1] != source || c.flags != flagCarry|flagZero|flagOverflow {
				t.Fatal("packed subtraction changed source/flags or propagated borrow between lanes")
			}
		})
	}
}

func TestPSUBQMemoryFaultPreservesDestination(t *testing.T) {
	for _, address := range []uint64{0x200000000, 0x200000001} {
		c, m := codeMemory(t, "660ffb02")
		c.registers[2] = address
		c.xmm[0][0] = 19
		before := c.xmm[0]
		c.flags = flagCarry
		if _, err := c.Step(m); err == nil {
			t.Fatal("expected memory fault")
		}
		if c.xmm[0] != before || c.flags != flagCarry {
			t.Fatal("fault changed architectural state")
		}
	}
}
