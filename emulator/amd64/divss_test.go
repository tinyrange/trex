package amd64

import (
	"encoding/binary"
	"github.com/tinyrange/trex/emulator/cpu"
	"testing"
)

func TestDIVSS(t *testing.T) {
	for _, tc := range []struct {
		a, b      uint32
		rc        uint64
		want      uint32
		precision bool
	}{
		{0x40c00000, 0x40000000, 0, 0x40400000, false},
		{0x80000000, 0xc0000000, 0, 0, false},
		{0x3f800000, 0x40400000, 0, 0x3eaaaaab, true},
		{0x3f800000, 0x40400000, 1, 0x3eaaaaaa, true},
		{0x3f800000, 0x40400000, 2, 0x3eaaaaab, true},
		{0xbf800000, 0x40400000, 1, 0xbeaaaaab, true},
		{0xbf800000, 0x40400000, 2, 0xbeaaaaaa, true},
		{0xbf800000, 0x40400000, 3, 0xbeaaaaaa, true},
		{0x3f800000, 0xc0400000, 2, 0xbeaaaaaa, true},
	} {
		for _, code := range []string{"f30f5ec1", "f30f5e02"} {
			c, m := codeMemory(t, code)
			c.xmm[0] = [16]byte{0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
			binary.LittleEndian.PutUint32(c.xmm[0][:4], tc.a)
			binary.LittleEndian.PutUint32(c.xmm[1][:4], tc.b)
			c.registers[2] = 0x200000003
			if err := m.Map(c.registers[2], c.xmm[1][:4], cpu.Read); err != nil {
				t.Fatal(err)
			}
			before := c.xmm[0]
			control := uint64(0x1f80) | tc.rc<<13
			c.setMXCSR(control)
			c.flags = flagCarry
			if _, err := c.Step(m); err != nil {
				t.Fatal(err)
			}
			if got := binary.LittleEndian.Uint32(c.xmm[0][:4]); got != tc.want {
				t.Fatalf("%x/%x rc%d got%x want%x", tc.a, tc.b, tc.rc, got, tc.want)
			}
			for i := 4; i < 16; i++ {
				if c.xmm[0][i] != before[i] {
					t.Fatal("upper lane changed")
				}
			}
			if tc.precision {
				control |= 1 << 5
			}
			if c.readMXCSR() != control || c.flags != flagCarry {
				t.Fatal("flags")
			}
		}
	}
}
func TestDIVSSStops(t *testing.T) {
	for _, tc := range []struct {
		a, b    uint32
		control uint64
	}{
		{0x3f800000, 0x40400000, 0xf80}, // Unmasked precision.
		{0x3f800000, 0, 0x1f80}, {1, 0x3f800000, 0x1f80},
		{0x7fc00000, 0x3f800000, 0x1f80}, {0x7f7fffff, 0x00800000, 0x1f80},
	} {
		c, m := codeMemory(t, "f30f5ec1")
		binary.LittleEndian.PutUint32(c.xmm[0][:4], tc.a)
		binary.LittleEndian.PutUint32(c.xmm[1][:4], tc.b)
		c.setMXCSR(tc.control)
		before, pc := c.xmm[0], c.PC()
		if _, err := c.Step(m); err == nil {
			t.Fatal("expected stop")
		}
		if c.xmm[0] != before || c.PC() != pc {
			t.Fatal("stop changed destination/PC")
		}
	}
}
