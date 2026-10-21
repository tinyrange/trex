package amd64

import (
	"bytes"
	"encoding/binary"
	"github.com/tinyrange/trex/emulator/cpu"
	"testing"
)

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
