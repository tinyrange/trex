package amd64

import (
	"github.com/tinyrange/trex/emulator/cpu"
	"testing"
)

func TestWordSearchSIMD(t *testing.T) {
	for _, code := range []string{"660f75c1", "660f7502", "0f56c1", "0f5602", "660f74c1", "660f7402"} {
		c, m := codeMemory(t, code)
		c.xmm[0] = [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
		c.xmm[1] = [16]byte{1, 2, 3, 0, 0, 6, 0, 0, 9, 10, 12, 11, 13, 14, 15, 16}
		a, b := c.xmm[0], c.xmm[1]
		c.registers[2] = 0x200000000
		if err := m.Map(c.registers[2], b[:], cpu.Read); err != nil {
			t.Fatal(err)
		}
		c.flags = flagCarry | flagZero
		if _, err := c.Step(m); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 16; i++ {
			want := a[i] | b[i]
			if code[4:6] == "74" {
				want = 0
				if a[i] == b[i] {
					want = 255
				}
			} else if code[:2] == "66" {
				want = 0
				j := i &^ 1
				if a[j] == b[j] && a[j+1] == b[j+1] {
					want = 255
				}
			}
			if c.xmm[0][i] != want {
				t.Fatalf("%s lane%d got%x want%x", code, i, c.xmm[0][i], want)
			}
		}
		if c.flags != flagCarry|flagZero {
			t.Fatal("flags")
		}
	}
	c, m := codeMemory(t, "660fd7c1")
	c.registers[0] = ^uint64(0)
	c.xmm[1] = [16]byte{0x80, 0x7f, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x80}
	before := c.xmm
	c.flags = flagCarry
	if _, err := c.Step(m); err != nil {
		t.Fatal(err)
	}
	if c.registers[0] != 0x8005 || c.flags != flagCarry || c.xmm != before {
		t.Fatal("PMOVMSKB")
	}
}
