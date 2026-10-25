package amd64

import (
	"github.com/tinyrange/trex/emulator/cpu"
	"testing"
)

func TestMOVHPS(t *testing.T) {
	for _, store := range []bool{false, true} {
		code := "0f 16 00"
		if store {
			code = "0f 17 00"
		}
		c, m := codeMemory(t, code)
		data := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9}
		c.registers[0] = 0x600000001
		if err := m.Map(0x600000000, data, cpu.Read|cpu.Write); err != nil {
			t.Fatal(err)
		}
		for i := range c.xmm[0] {
			c.xmm[0][i] = byte(32 + i)
		}
		before := c.xmm[0]
		c.flags = flagCarry
		if _, err := c.Step(m); err != nil {
			t.Fatal(err)
		}
		if store {
			value, err := readWord(m, c.registers[0], 8)
			var got [8]byte
			for i := range got {
				got[i] = byte(value >> uint(i*8))
			}
			if err != nil {
				t.Fatal(err)
			}
			for i, b := range got {
				if b != before[i+8] {
					t.Fatal("wrong stored lane")
				}
			}
		} else {
			for i := 0; i < 8; i++ {
				if c.xmm[0][i] != before[i] || c.xmm[0][i+8] != data[i+1] {
					t.Fatal("wrong moved lane")
				}
			}
		}
		if c.flags != flagCarry {
			t.Fatal("flags changed")
		}
	}
}
