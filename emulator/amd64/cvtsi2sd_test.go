package amd64

import (
	"encoding/binary"
	"testing"

	"github.com/tinyrange/trex/emulator/cpu"
)

func TestCVTSI2SDRoundingAndPreservation(t *testing.T) {
	for _, tc := range []struct {
		name      string
		value     int64
		rounding  uint64
		bits      uint64
		precision bool
	}{
		{"zero", 0, 0, 0, false},
		{"negative", -35, 0, 0xc041800000000000, false},
		{"tie-even", 1<<53 + 1, 0, 0x4340000000000000, true},
		{"tie-odd", 1<<53 + 3, 0, 0x4340000000000002, true},
		{"up", 1<<53 + 1, 2, 0x4340000000000001, true},
		{"down", 1<<53 + 1, 1, 0x4340000000000000, true},
		{"negative-down", -(1<<53 + 1), 1, 0xc340000000000001, true},
		{"negative-up", -(1<<53 + 1), 2, 0xc340000000000000, true},
		{"negative-truncate", -(1<<53 + 3), 3, 0xc340000000000001, true},
		{"min64", -1 << 63, 0, 0xc3e0000000000000, false},
		{"max64", 1<<63 - 1, 0, 0x43e0000000000000, true},
		{"max64-truncate", 1<<63 - 1, 3, 0x43dfffffffffffff, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, code := range []string{"f2480f2ac2", "f2480f2a02"} {
				c, m := codeMemory(t, code)
				c.registers[2] = uint64(tc.value)
				if code == "f2480f2a02" {
					var data [8]byte
					binary.LittleEndian.PutUint64(data[:], uint64(tc.value))
					c.registers[2] = 0x200000003
					if err := m.Map(c.registers[2], data[:], cpu.Read); err != nil {
						t.Fatal(err)
					}
				}
				c.xmm[0] = [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
				before := c.xmm[0]
				control := uint64(0x1f80) | tc.rounding<<13
				c.setMXCSR(control)
				c.flags = flagCarry | flagZero
				if _, err := c.Step(m); err != nil {
					t.Fatal(err)
				}
				if got := binary.LittleEndian.Uint64(c.xmm[0][:8]); got != tc.bits {
					t.Fatalf("%s result %016x want %016x", code, got, tc.bits)
				}
				for i := 8; i < 16; i++ {
					if c.xmm[0][i] != before[i] {
						t.Fatal("upper lane modified")
					}
				}
				if tc.precision {
					control |= 1 << 5
				}
				if c.readMXCSR() != control || c.flags != flagCarry|flagZero {
					t.Fatal("flags modified incorrectly")
				}
			}
		})
	}
}

func TestCVTSI2SDSignedDwordAndFaultAtomicity(t *testing.T) {
	for _, code := range []string{"f20f2ac2", "f20f2a02"} {
		c, m := codeMemory(t, code)
		c.registers[2] = 0x12345678ffffffff
		if code == "f20f2a02" {
			c.registers[2] = 0x200000003
			// Only four readable bytes: a qword read would fault.
			if err := m.Map(c.registers[2], []byte{255, 255, 255, 255}, cpu.Read); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := c.Step(m); err != nil {
			t.Fatal(err)
		}
		if got := binary.LittleEndian.Uint64(c.xmm[0][:8]); got != 0xbff0000000000000 {
			t.Fatalf("dword sign %x", got)
		}
	}
	for _, code := range []string{"f2480f2ac2", "f2480f2a02"} {
		c, m := codeMemory(t, code)
		c.registers[2] = 1<<53 + 1
		c.setMXCSR(0xf80) // Precision exception unmasked.
		c.xmm[0] = [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9}
		before, pc := c.xmm[0], c.PC()
		if _, err := c.Step(m); err == nil {
			t.Fatal("expected precision or memory fault")
		}
		if c.xmm[0] != before || c.PC() != pc {
			t.Fatal("fault modified destination or PC")
		}
		want := uint64(0xf80)
		if code == "f2480f2ac2" {
			want |= 1 << 5
		}
		if c.readMXCSR() != want {
			t.Fatalf("fault flags %x want %x", c.readMXCSR(), want)
		}
	}
}
