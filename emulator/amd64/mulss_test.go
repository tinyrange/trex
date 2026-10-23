package amd64

import (
	"encoding/binary"
	"testing"
)

func TestMULSS(t *testing.T) {
	for _, tc := range []struct {
		a, b      uint32
		rc        uint64
		want      uint32
		precision bool
	}{
		{0x40400000, 0xc0000000, 0, 0xc0c00000, false},
		{0, 0xc0000000, 0, 0x80000000, false}, {0xc0000000, 0, 0, 0x80000000, false},
		{0x3f800001, 0x3f800001, 0, 0x3f800002, true},
		{0x3f800001, 0x3f800001, 2, 0x3f800003, true},
		{0xbf800001, 0x3f800001, 1, 0xbf800003, true},
		{0xbf800001, 0x3f800001, 3, 0xbf800002, true},
	} {
		c, m := codeMemory(t, "f30f59c1")
		c.xmm[0] = [16]byte{0, 0, 0, 0, 1, 2, 3, 4}
		binary.LittleEndian.PutUint32(c.xmm[0][:4], tc.a)
		binary.LittleEndian.PutUint32(c.xmm[1][:4], tc.b)
		before := c.xmm[0]
		control := uint64(0x1f80) | tc.rc<<13
		c.setMXCSR(control)
		c.flags = flagCarry
		if _, err := c.Step(m); err != nil {
			t.Fatal(err)
		}
		if got := binary.LittleEndian.Uint32(c.xmm[0][:4]); got != tc.want {
			t.Fatalf("got%x want%x", got, tc.want)
		}
		for i := 4; i < 16; i++ {
			if c.xmm[0][i] != before[i] {
				t.Fatal("upper lane")
			}
		}
		if tc.precision {
			control |= 32
		}
		if c.readMXCSR() != control || c.flags != flagCarry {
			t.Fatal("flags")
		}
	}
}
