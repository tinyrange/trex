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

func TestMOVQVectorFormsAndFaults(t *testing.T) {
	for _, code := range []string{"f3 0f 7e 06", "f3 0f 7e c1", "66 48 0f 6e c0"} {
		t.Run(code, func(t *testing.T) {
			c, m := codeMemory(t, code)
			const value = uint64(0xfedcba9876543210)
			c.registers[0] = value
			c.registers[6] = 0x600000003
			for i := range c.xmm[0] {
				c.xmm[0][i] = 0xaa
			}
			binary.LittleEndian.PutUint64(c.xmm[1][:8], value)
			data := make([]byte, 8)
			binary.LittleEndian.PutUint64(data, value)
			if err := m.Map(c.registers[6], data, cpu.Read); err != nil {
				t.Fatal(err)
			}
			c.flags = flagCarry | flagZero
			flags := c.flags
			if _, err := c.Step(m); err != nil {
				t.Fatal(err)
			}
			if binary.LittleEndian.Uint64(c.xmm[0][:8]) != value || !bytes.Equal(c.xmm[0][8:], make([]byte, 8)) || c.flags != flags {
				t.Fatal("MOVQ load/copy failed or modified flags/upper lane")
			}
		})
	}
	for _, code := range []string{"66 0f d6 06", "66 48 0f 7e c0"} {
		t.Run(code, func(t *testing.T) {
			c, m := codeMemory(t, code)
			c.registers[6] = 0x600000003
			data := bytes.Repeat([]byte{0xaa}, 16)
			if err := m.Map(c.registers[6], data, cpu.Read|cpu.Write); err != nil {
				t.Fatal(err)
			}
			binary.LittleEndian.PutUint64(c.xmm[0][:8], 0xfedcba9876543210)
			if _, err := c.Step(m); err != nil {
				t.Fatal(err)
			}
			if code == "66 48 0f 7e c0" {
				if c.registers[0] != 0xfedcba9876543210 {
					t.Fatal("MOVQ truncated GPR")
				}
			} else {
				got := make([]byte, 16)
				if err := m.ReadMemory(c.registers[6], got, cpu.Read); err != nil {
					t.Fatal(err)
				}
				if binary.LittleEndian.Uint64(got) != 0xfedcba9876543210 || !bytes.Equal(got[8:], data[8:]) {
					t.Fatal("MOVQ store changed extent")
				}
			}
		})
	}
	c, m := codeMemory(t, "f3 0f 7e 06")
	c.registers[6] = 0x700000000
	c.xmm[0][15] = 0xaa
	before := *c
	if _, err := c.Step(m); err == nil || *c != before {
		t.Fatal("faulting MOVQ changed CPU state")
	}
}
