package amd64

import (
	"encoding/binary"
	"github.com/tinyrange/trex/emulator/cpu"
	"testing"
)

func TestCVTSI2SS(t *testing.T) {
	for _, tc := range []struct {
		name      string
		value     int64
		rc        uint64
		want      uint32
		precision bool
	}{
		{"zero", 0, 0, 0, false}, {"negative", -35, 0, 0xc20c0000, false},
		{"tie-even", 16777217, 0, 0x4b800000, true}, {"tie-odd", 16777219, 0, 0x4b800002, true},
		{"up", 16777217, 2, 0x4b800001, true}, {"down", 16777217, 1, 0x4b800000, true},
		{"negative-down", -16777217, 1, 0xcb800001, true}, {"negative-up", -16777217, 2, 0xcb800000, true},
		{"truncate", -16777219, 3, 0xcb800001, true},
		{"min64", -1 << 63, 0, 0xdf000000, false}, {"max64", 1<<63 - 1, 0, 0x5f000000, true},
		{"max64-truncate", 1<<63 - 1, 3, 0x5effffff, true},
		// Just above a binary32 midpoint, but binary64 would lose the +1.
		{"double-rounding", 1<<62 + 1<<38 + 1, 0, 0x5e800001, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, code := range []string{"f3480f2ac2", "f3480f2a02"} {
				c, m := codeMemory(t, code)
				c.registers[2] = uint64(tc.value)
				if code == "f3480f2a02" {
					var data [8]byte
					binary.LittleEndian.PutUint64(data[:], uint64(tc.value))
					c.registers[2] = 0x200000003
					if err := m.Map(c.registers[2], data[:], cpu.Read); err != nil {
						t.Fatal(err)
					}
				}
				c.xmm[0] = [16]byte{9, 8, 7, 6, 5, 4, 3, 2, 1, 2, 3, 4, 5, 6, 7, 8}
				before := c.xmm[0]
				control := uint64(0x1f80) | tc.rc<<13
				c.setMXCSR(control)
				c.flags = flagCarry | flagZero
				if _, err := c.Step(m); err != nil {
					t.Fatal(err)
				}
				if got := binary.LittleEndian.Uint32(c.xmm[0][:4]); got != tc.want {
					t.Fatalf("%s got%x want%x", code, got, tc.want)
				}
				for i := 4; i < 16; i++ {
					if c.xmm[0][i] != before[i] {
						t.Fatal("upper lane changed")
					}
				}
				if tc.precision {
					control |= 1 << 5
				}
				if c.readMXCSR() != control || c.flags != flagCarry|flagZero {
					t.Fatal("flags")
				}
			}
		})
	}
}
func TestCVTSI2SSSignedDwordAndFaults(t *testing.T) {
	c, m := codeMemory(t, "f30f2ac2")
	c.registers[2] = 0x12345678ffffffff
	if _, err := c.Step(m); err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint32(c.xmm[0][:4]); got != 0xbf800000 {
		t.Fatalf("dword sign: %x", got)
	}
	for _, code := range []string{"f3480f2ac2", "f3480f2a02"} {
		c, m = codeMemory(t, code)
		c.registers[2] = 16777217
		c.setMXCSR(0xf80)
		c.xmm[0] = [16]byte{1, 2, 3, 4, 5}
		before, pc := c.xmm[0], c.PC()
		if _, err := c.Step(m); err == nil {
			t.Fatal("expected exception")
		}
		if c.xmm[0] != before || c.PC() != pc {
			t.Fatal("fault changed destination/PC")
		}
		want := uint64(0xf80)
		if code == "f3480f2ac2" {
			want |= 1 << 5
		}
		if c.readMXCSR() != want {
			t.Fatalf("fault flags %x", c.readMXCSR())
		}
	}
}
