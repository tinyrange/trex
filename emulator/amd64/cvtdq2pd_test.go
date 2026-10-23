package amd64

import (
	"encoding/binary"
	"github.com/tinyrange/trex/emulator/cpu"
	"math"
	"testing"
)

func TestCVTDQ2PDExactSignedConversion(t *testing.T) {
	for _, code := range []string{"f30fe6c0", "f30fe602"} {
		for _, pair := range [][2]int32{{-2147483648, 2147483647}, {-1, 0}, {16777217, -16777217}} {
			c, m := codeMemory(t, code)
			var input [8]byte
			binary.LittleEndian.PutUint32(input[:4], uint32(pair[0]))
			binary.LittleEndian.PutUint32(input[4:], uint32(pair[1]))
			copy(c.xmm[0][:], input[:])
			copy(c.xmm[0][8:], []byte{1, 2, 3, 4, 5, 6, 7, 8})
			c.registers[2] = 0x200000003
			if err := m.Map(c.registers[2], input[:], cpu.Read); err != nil {
				t.Fatal(err)
			}
			c.flags = flagCarry | flagZero
			if _, err := c.Step(m); err != nil {
				t.Fatal(err)
			}
			for i, want := range pair {
				got := math.Float64frombits(binary.LittleEndian.Uint64(c.xmm[0][i*8:]))
				if got != float64(want) {
					t.Fatalf("%s lane%d=%v want%d", code, i, got, want)
				}
			}
			if c.flags != flagCarry|flagZero {
				t.Fatalf("flags=%x", c.flags)
			}
		}
	}
}
