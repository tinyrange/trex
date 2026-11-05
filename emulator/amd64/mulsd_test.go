package amd64

import (
	"encoding/binary"
	"github.com/tinyrange/trex/emulator/cpu"
	"testing"
)

func TestMULSDExactProductAndRounding(t *testing.T) {
	for _, tc := range []struct {
		name         string
		a, b, result uint64
		rounding     uint64
		precision    bool
	}{
		{"exact", 0x3ff8000000000000, 0x4000000000000000, 0x4008000000000000, 0, false},
		{"negative-zero", 0x8000000000000000, 0x3ff0000000000000, 0x8000000000000000, 0, false},
		{"two-negatives", 0x8000000000000000, 0xbff0000000000000, 0, 0, false},
		{"nearest", 0x3ff0000000000001, 0x3ff0000000000001, 0x3ff0000000000002, 0, true},
		{"up", 0x3ff0000000000001, 0x3ff0000000000001, 0x3ff0000000000003, 2, true},
		{"down", 0x3ff0000000000001, 0x3ff0000000000001, 0x3ff0000000000002, 1, true},
		{"negative-down", 0xbff0000000000001, 0x3ff0000000000001, 0xbff0000000000003, 1, true},
		{"negative-up", 0xbff0000000000001, 0x3ff0000000000001, 0xbff0000000000002, 2, true},
		{"negative-truncate", 0xbff0000000000001, 0x3ff0000000000001, 0xbff0000000000002, 3, true},
		{"tie-even", 0x3ff0000000000001, 0x3ff8000000000000, 0x3ff8000000000002, 0, true},
		{"exponent-carry", 0x3fffffffffffffff, 0x3ff0000000000001, 0x4000000000000000, 0, true},
		{"exponent-carry-up", 0x3fffffffffffffff, 0x3ff0000000000001, 0x4000000000000001, 2, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, code := range []string{"f20f59c1", "f20f5902"} {
				c, m := codeMemory(t, code)
				c.xmm[0] = [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
				binary.LittleEndian.PutUint64(c.xmm[0][:8], tc.a)
				binary.LittleEndian.PutUint64(c.xmm[1][:8], tc.b)
				if code == "f20f5902" {
					c.registers[2] = 0x200000003
					var data [8]byte
					binary.LittleEndian.PutUint64(data[:], tc.b)
					if err := m.Map(c.registers[2], data[:], cpu.Read); err != nil {
						t.Fatal(err)
					}
				}
				before := c.xmm[0]
				control := uint64(0x1f80) | tc.rounding<<13
				c.setMXCSR(control)
				c.flags = flagCarry | flagZero
				if _, err := c.Step(m); err != nil {
					t.Fatal(err)
				}
				if got := binary.LittleEndian.Uint64(c.xmm[0][:8]); got != tc.result {
					t.Fatalf("got %016x want %016x", got, tc.result)
				}
				for i := 8; i < 16; i++ {
					if c.xmm[0][i] != before[i] {
						t.Fatal("upper lane changed")
					}
				}
				if tc.precision {
					control |= 1 << 5
				}
				if c.readMXCSR() != control || c.flags != flagCarry|flagZero {
					t.Fatal("flags changed incorrectly")
				}
			}
		})
	}
}
func TestMULSDFaultAtomicityAndExplicitRanges(t *testing.T) {
	for _, tc := range []struct {
		name, code            string
		a, b, control, status uint64
	}{
		{"precision", "f20f59c1", 0x3ff0000000000001, 0x3ff0000000000001, 0xf80, 0xfa0},
		{"unmapped", "f20f5902", 0x3ff0000000000000, 0, 0x1f80, 0x1f80},
		{"subnormal", "f20f59c1", 1, 0x3ff0000000000000, 0x1f80, 0x1f80},
		{"infinity", "f20f59c1", 0x7ff0000000000000, 0x3ff0000000000000, 0x1f80, 0x1f80},
		{"overflow", "f20f59c1", 0x7fefffffffffffff, 0x4000000000000000, 0x1f80, 0x1f80},
		{"underflow", "f20f59c1", 0x0010000000000000, 0x3fe0000000000000, 0x1f80, 0x1f80},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, m := codeMemory(t, tc.code)
			binary.LittleEndian.PutUint64(c.xmm[0][:8], tc.a)
			binary.LittleEndian.PutUint64(c.xmm[1][:8], tc.b)
			c.setMXCSR(tc.control)
			before, pc := c.xmm[0], c.PC()
			if _, err := c.Step(m); err == nil {
				t.Fatal("expected explicit stop")
			}
			if c.xmm[0] != before || c.PC() != pc || c.readMXCSR() != tc.status {
				t.Fatal("fault state changed")
			}
		})
	}
}
