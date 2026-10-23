package amd64

import (
	"encoding/binary"
	"math"
	"testing"
)

func TestCVTPS2PDControlAndSpecialValues(t *testing.T) {
	for _, tc := range []struct {
		name    string
		input   [2]uint32
		control uint64
		want    [2]uint64
		flags   uint64
		fault   bool
	}{
		{"finite", [2]uint32{0x3fc00000, 0xc0200000}, 0x1f80, [2]uint64{math.Float64bits(1.5), math.Float64bits(-2.5)}, 0, false},
		{"zeros", [2]uint32{0, 0x80000000}, 0x1f80, [2]uint64{0, 1 << 63}, 0, false},
		{"infinities", [2]uint32{0x7f800000, 0xff800000}, 0x1f80, [2]uint64{0x7ff0000000000000, 0xfff0000000000000}, 0, false},
		{"nan", [2]uint32{0x7fc00001, 0xff800002}, 0x1f80, [2]uint64{0x7ff8000020000000, 0xfff8000040000000}, 1, false},
		{"denormal", [2]uint32{1, 0x80000001}, 0x1f80, [2]uint64{math.Float64bits(math.Ldexp(1, -149)), math.Float64bits(-math.Ldexp(1, -149))}, 2, false},
		{"daz", [2]uint32{1, 0x80000001}, 0x1fc0, [2]uint64{0, 1 << 63}, 0, false},
		{"unmasked", [2]uint32{0x7f800001, 0}, 0x1f00, [2]uint64{}, 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, m := codeMemory(t, "0f5ac1")
			c.setMXCSR(tc.control)
			for i, x := range tc.input {
				binary.LittleEndian.PutUint32(c.xmm[1][i*4:], x)
			}
			c.xmm[0] = [16]byte{1, 2, 3, 4, 5}
			before, pc := c.xmm[0], c.PC()
			c.flags = flagCarry | flagZero
			_, err := c.Step(m)
			if (err != nil) != tc.fault {
				t.Fatalf("fault=%v err=%v", tc.fault, err)
			}
			if tc.fault {
				if c.xmm[0] != before || c.PC() != pc {
					t.Fatal("fault changed destination or PC")
				}
			} else {
				for i, want := range tc.want {
					if got := binary.LittleEndian.Uint64(c.xmm[0][i*8:]); got != want {
						t.Fatalf("lane%d=%x want%x", i, got, want)
					}
				}
			}
			if c.readMXCSR() != tc.control|tc.flags || c.flags != flagCarry|flagZero {
				t.Fatalf("MXCSR=%x flags=%x", c.readMXCSR(), c.flags)
			}
		})
	}
}
