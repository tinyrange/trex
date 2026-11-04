package amd64

import (
	"encoding/binary"
	"github.com/tinyrange/trex/emulator/cpu"
	"testing"
)

func TestPackedDwordAdditionWrapsEachLane(t *testing.T) {
	for _, tc := range []struct {
		name, code   string
		memory, self bool
	}{
		{"register", "660ffec1", false, false},
		{"memory", "660ffe02", true, false},
		{"self", "660ffec0", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, m := codeMemory(t, tc.code)
			left := [4]uint32{0xffffffff, 0x80000000, 0x01020304, 7}
			right := [4]uint32{1, 0x80000000, 0xff000000, 9}
			if tc.self {
				right = left
			}
			for i := 0; i < 4; i++ {
				binary.LittleEndian.PutUint32(c.xmm[0][i*4:], left[i])
				binary.LittleEndian.PutUint32(c.xmm[1][i*4:], right[i])
			}
			if tc.memory {
				c.registers[2] = 0x200000000
				if err := m.Map(c.registers[2], c.xmm[1][:], cpu.Read); err != nil {
					t.Fatal(err)
				}
			}
			c.flags = flagCarry | flagOverflow | flagZero
			if _, err := c.Step(m); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 4; i++ {
				if got := binary.LittleEndian.Uint32(c.xmm[0][i*4:]); got != left[i]+right[i] {
					t.Fatalf("lane%d=%x", i, got)
				}
			}
			if c.flags != flagCarry|flagOverflow|flagZero {
				t.Fatal("packed integer addition changed scalar flags")
			}
		})
	}
}
