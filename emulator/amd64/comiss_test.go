package amd64

import (
	"encoding/binary"
	"github.com/tinyrange/trex/emulator/cpu"
	"testing"
)

func TestCOMISS(t *testing.T) {
	for _, tc := range []struct {
		a, b                   uint32
		control, flags, status uint64
		fault                  bool
	}{
		{0x3f800000, 0x40000000, 0x1f80, flagCarry, 0, false},
		{0x40000000, 0x3f800000, 0x1f80, 0, 0, false},
		{0x80000000, 0, 0x1f80, flagZero, 0, false},
		{0x7f800000, 0x7f800000, 0x1f80, flagZero, 0, false},
		{0x7fc00001, 0, 0x1f80, flagZero | flagParity | flagCarry, 1, false},
		{0, 0xff800001, 0x1f80, flagZero | flagParity | flagCarry, 1, false},
		{0x7fc00001, 0, 0x1f00, 0, 1, true},
		{1, 0, 0x1f80, 0, 2, false}, {1, 0, 0x1fc0, flagZero, 0, false},
		{1, 0, 0x1e80, 0, 2, true},
	} {
		for _, code := range []string{"0f2fc1", "0f2f02"} {
			c, m := codeMemory(t, code)
			binary.LittleEndian.PutUint32(c.xmm[0][:4], tc.a)
			binary.LittleEndian.PutUint32(c.xmm[1][:4], tc.b)
			c.registers[2] = 0x200000003
			if err := m.Map(c.registers[2], c.xmm[1][:4], cpu.Read); err != nil {
				t.Fatal(err)
			}
			c.setMXCSR(tc.control)
			c.flags = 0xad7
			before, pc, flags := c.xmm, c.PC(), c.flags
			_, err := c.Step(m)
			if (err != nil) != tc.fault {
				t.Fatalf("fault=%v err=%v", tc.fault, err)
			}
			want := uint64(0x202) | tc.flags
			if tc.fault {
				want = flags
				if c.PC() != pc {
					t.Fatal("fault changed PC")
				}
			}
			if c.flags != want || c.xmm != before || c.readMXCSR() != tc.control|tc.status {
				t.Fatalf("flags%x want%x MXCSR%x", c.flags, want, c.readMXCSR())
			}
		}
	}
}
