package amd64

import (
	"bytes"
	"testing"

	"github.com/tinyrange/trex/emulator/cpu"
)

func TestNonTemporalIntegerStore(t *testing.T) {
	for _, tc := range []struct {
		code  string
		width int
	}{{"0f c3 11", 4}, {"48 0f c3 11", 8}} {
		t.Run(tc.code, func(t *testing.T) {
			c, m := codeMemory(t, tc.code)
			const base = 0x600000000
			if err := m.Map(base, bytes.Repeat([]byte{0xaa}, 16), cpu.Read|cpu.Write); err != nil {
				t.Fatal(err)
			}
			c.registers[1], c.registers[2] = base+4, 0x123456789abcdef0
			c.flags = flagCarry | flagZero | flagDirection
			registers, flags := c.registers, c.flags
			if _, err := c.Step(m); err != nil {
				t.Fatal(err)
			}
			got, err := readWord(m, base+4, tc.width)
			if err != nil || got != registers[2]&mask(tc.width) {
				t.Fatalf("store = %#x, %v", got, err)
			}
			for _, address := range []uint64{base, base + 4 + uint64(tc.width)} {
				guard, err := readWord(m, address, 4)
				if err != nil || guard != 0xaaaaaaaa {
					t.Fatalf("guard at %#x = %#x, %v", address, guard, err)
				}
			}
			if c.registers != registers || c.flags != flags {
				t.Fatal("store changed registers or flags")
			}
		})
	}
}

func TestNonTemporalIntegerStoreFault(t *testing.T) {
	c, m := codeMemory(t, "48 0f c3 11")
	c.registers[1] = 0x600000000
	before := *c
	if _, err := c.Step(m); err == nil {
		t.Fatal("unmapped store did not fault")
	}
	if c.rip != before.rip || c.registers != before.registers || c.flags != before.flags {
		t.Fatal("fault changed architectural state")
	}
}
