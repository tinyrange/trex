package amd64

import (
	"encoding/binary"
	"testing"
)

func TestPackedIntegerOperations(t *testing.T) {
	for _, test := range []struct {
		name, code        string
		left, right, want [2]uint64
	}{
		{"paddq", "660fd4c1", [2]uint64{^uint64(0), 10}, [2]uint64{1, 5}, [2]uint64{0, 15}},
		{"pcmpeqd", "660f76c1", [2]uint64{0x12345678, 0x100000002}, [2]uint64{0x112345678, 0x100000003}, [2]uint64{0xffffffff, 0xffffffff00000000}},
		{"punpckhdq", "660f6ac1", [2]uint64{0, 0x200000001}, [2]uint64{0, 0x400000003}, [2]uint64{0x300000001, 0x400000002}},
	} {
		t.Run(test.name, func(t *testing.T) {
			c, m := codeMemory(t, test.code)
			for i := range test.left {
				binary.LittleEndian.PutUint64(c.xmm[0][8*i:], test.left[i])
				binary.LittleEndian.PutUint64(c.xmm[1][8*i:], test.right[i])
			}
			c.flags = flagCarry | flagOverflow | flagZero
			if _, err := c.Step(m); err != nil {
				t.Fatal(err)
			}
			got := [2]uint64{binary.LittleEndian.Uint64(c.xmm[0][:]), binary.LittleEndian.Uint64(c.xmm[0][8:])}
			if got != test.want || c.flags != flagCarry|flagOverflow|flagZero {
				t.Fatalf("lanes = %#x, want %#x; flags = %#x", got, test.want, c.flags)
			}
		})
	}
}
