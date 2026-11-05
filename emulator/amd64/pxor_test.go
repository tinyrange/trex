package amd64

import (
	"github.com/tinyrange/trex/emulator/cpu"
	"testing"
)

func TestPXORXMM(t *testing.T) {
	for _, code := range []string{"66 0f ef c1", "66 0f ef 00"} {
		c, m := codeMemory(t, code)
		var source [16]byte
		var expected [16]byte
		for i := range source {
			source[i] = byte(i * 13)
			c.xmm[0][i] = byte(255 - i)
			expected[i] = source[i] ^ c.xmm[0][i]
		}
		c.xmm[1] = source
		c.registers[0] = 0x600000000
		if err := m.Map(c.registers[0], source[:], cpu.Read); err != nil {
			t.Fatal(err)
		}
		c.flags = flagCarry | flagZero | flagOverflow
		flags := c.flags
		if _, err := c.Step(m); err != nil {
			t.Fatal(err)
		}
		if c.xmm[0] != expected || c.xmm[1] != source || c.flags != flags {
			t.Fatal("PXOR result/source/flags corrupted")
		}
	}
	c, m := codeMemory(t, "66 45 0f ef ff") // PXOR X15,X15
	for i := range c.xmm[15] {
		c.xmm[15][i] = 255
	}
	if _, err := c.Step(m); err != nil {
		t.Fatal(err)
	}
	if c.xmm[15] != [16]byte{} {
		t.Fatal("high register did not clear")
	}
}
