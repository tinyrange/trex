package amd64

import (
	"github.com/tinyrange/trex/emulator/cpu"
	"testing"
)

func TestPSHUFLW(t *testing.T) {
	for _, tc := range []struct {
		code string
		want [16]byte
	}{
		{"f20f70c800", [16]byte{1, 2, 1, 2, 1, 2, 1, 2, 9, 10, 11, 12, 13, 14, 15, 16}},
		{"f20f70c01b", [16]byte{7, 8, 5, 6, 3, 4, 1, 2, 9, 10, 11, 12, 13, 14, 15, 16}},
		{"f20f700a1b", [16]byte{7, 8, 5, 6, 3, 4, 1, 2, 9, 10, 11, 12, 13, 14, 15, 16}},
	} {
		c, m := codeMemory(t, tc.code)
		c.xmm[0] = [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
		c.registers[2] = 0x200000000
		if err := m.Map(c.registers[2], c.xmm[0][:], cpu.Read); err != nil {
			t.Fatal(err)
		}
		c.flags = flagCarry | flagZero
		if _, err := c.Step(m); err != nil {
			t.Fatal(err)
		}
		dst := 1
		if tc.code == "f20f70c01b" {
			dst = 0
		}
		if c.xmm[dst] != tc.want || c.flags != flagCarry|flagZero {
			t.Fatalf("%s got%x", tc.code, c.xmm[dst])
		}
	}
	for _, size := range []int{8, 16} {
		c, m := codeMemory(t, "f20f700a1b")
		c.registers[2] = 0x200000000
		if size == 16 {
			c.registers[2]++
		}
		if err := m.Map(c.registers[2], make([]byte, size), cpu.Read); err != nil {
			t.Fatal(err)
		}
		c.xmm[1] = [16]byte{1, 2}
		before, pc := c.xmm[1], c.PC()
		if _, err := c.Step(m); err == nil {
			t.Fatal("expected memory/alignment fault")
		}
		if c.xmm[1] != before || c.PC() != pc {
			t.Fatal("fault changed destination/PC")
		}
	}
}
