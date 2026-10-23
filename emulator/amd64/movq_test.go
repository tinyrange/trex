package amd64

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/tinyrange/trex/emulator/cpu"
)

func TestMOVQGeneralAndVectorRegisters(t *testing.T) {
	// OneDrive's CRT uses movq xmm0,r11. Exercise both GPR directions and
	// the separate F3 vector encoding with dirty upper lanes.
	c, m := codeMemory(t, "66490f6ec3 f30f7ec8 66490f7eca f4")
	c.registers[11] = 0xfedcba9876543210
	for i := range c.xmm[0] {
		c.xmm[0][i], c.xmm[1][i] = 0xff, 0xff
	}
	c.flags = flagCarry | flagZero | flagOverflow
	runCode(t, c, m, 4)
	requireRegister(t, c, "r10", 0xfedcba9876543210)
	for _, reg := range []int{0, 1} {
		if binary.LittleEndian.Uint64(c.xmm[reg][:8]) != c.registers[11] || !bytes.Equal(c.xmm[reg][8:], make([]byte, 8)) {
			t.Fatalf("xmm%d=%x", reg, c.xmm[reg])
		}
	}
	if c.flags != flagCarry|flagZero|flagOverflow {
		t.Fatalf("flags=%x", c.flags)
	}
}

func TestMOVQMemoryExtentAndFault(t *testing.T) {
	for _, code := range []string{"f3440f7e0a", "664c0f6e0a"} {
		t.Run(code, func(t *testing.T) {
			// Both load encodings read exactly eight unaligned bytes.
			c, m := codeMemory(t, code+" 66440fd609 f4")
			const address = 0x200000003
			data := []byte{1, 2, 3, 4, 5, 6, 7, 0xf8}
			if err := m.Map(address, data, cpu.Read|cpu.Write); err != nil {
				t.Fatal(err)
			}
			c.registers[2], c.registers[1] = address, address
			c.xmm[9] = [16]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
			runCode(t, c, m, 3)
			if !bytes.Equal(c.xmm[9][:8], data) || !bytes.Equal(c.xmm[9][8:], make([]byte, 8)) {
				t.Fatalf("xmm9=%x", c.xmm[9])
			}
			got := make([]byte, 8)
			if err := m.ReadMemory(address, got, cpu.Read); err != nil || !bytes.Equal(got, data) {
				t.Fatalf("store=%x: %v", got, err)
			}
			// An inaccessible source must not clear the destination or advance PC.
			c, m = codeMemory(t, code)
			c.registers[2] = address
			before := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
			c.xmm[9] = before
			pc := c.PC()
			if _, err := c.Step(m); err == nil {
				t.Fatal("unmapped load succeeded")
			}
			if c.xmm[9] != before || c.PC() != pc {
				t.Fatal("fault changed architectural state")
			}
		})
	}
}
