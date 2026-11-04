package amd64

import (
	"encoding/binary"
	"github.com/tinyrange/trex/emulator/cpu"
	"testing"
)

func TestCVTTSD2SIWidthsAndSpecialValues(t *testing.T) {
	for _, tc := range []struct{ input, want32, want64, status32, status64 uint64 }{
		{0, 0, 0, 0, 0},
		{0x3ffc000000000000, 1, 1, 32, 32},
		{0xbffc000000000000, 0xffffffff, 0xffffffffffffffff, 32, 32},
		{0x41e0000000000000, 0x80000000, 0x80000000, 1, 0},
		{0x43e0000000000000, 0x80000000, 0x8000000000000000, 1, 1},
		{0xc3e0000000000000, 0x80000000, 0x8000000000000000, 1, 0},
		{0x43dfffffffffffff, 0x80000000, 0x7ffffffffffffc00, 1, 0},
		{0x7ff8000000000001, 0x80000000, 0x8000000000000000, 1, 1},
		{0x7ff0000000000000, 0x80000000, 0x8000000000000000, 1, 1},
		{1, 0, 0, 32, 32},
	} {
		for _, code := range []string{"f20f2cc0", "f2480f2cc0", "f20f2c02", "f2480f2c02"} {
			c, m := codeMemory(t, code)
			binary.LittleEndian.PutUint64(c.xmm[0][:8], tc.input)
			c.registers[0] = 0x12345678abcdef00
			c.registers[2] = 0x200000003
			if err := m.Map(c.registers[2], c.xmm[0][:8], cpu.Read); err != nil {
				t.Fatal(err)
			}
			// Truncation must ignore the ordinary rounding control.
			c.setMXCSR(0x5f80)
			c.flags = flagCarry | flagZero
			before := c.xmm
			if _, err := c.Step(m); err != nil {
				t.Fatal(err)
			}
			want, status := tc.want32, tc.status32
			if code == "f2480f2cc0" || code == "f2480f2c02" {
				want, status = tc.want64, tc.status64
			}
			if c.registers[0] != want || c.xmm != before || c.flags != flagCarry|flagZero || c.readMXCSR() != 0x5f80|status {
				t.Fatalf("%s result %x want %x MXCSR %x", code, c.registers[0], want, c.readMXCSR())
			}
		}
	}
}
func TestCVTTSD2SIDAZAndFaultAtomicity(t *testing.T) {
	c, m := codeMemory(t, "f2480f2cc0")
	binary.LittleEndian.PutUint64(c.xmm[0][:8], 1)
	c.setMXCSR(0x1fc0)
	if _, err := c.Step(m); err != nil || c.registers[0] != 0 || c.readMXCSR() != 0x1fc0 {
		t.Fatal("DAZ")
	}
	for _, tc := range []struct {
		code                   string
		input, control, status uint64
	}{
		{"f2480f2cc0", 0x3ffc000000000000, 0xf80, 0xfa0},
		{"f2480f2cc0", 0x7ff8000000000001, 0x1f00, 0x1f01},
		{"f2480f2c02", 0, 0x1f80, 0x1f80},
	} {
		c, m = codeMemory(t, tc.code)
		binary.LittleEndian.PutUint64(c.xmm[0][:8], tc.input)
		c.registers[0] = 0x12345678abcdef00
		c.setMXCSR(tc.control)
		pc := c.PC()
		if _, err := c.Step(m); err == nil || c.PC() != pc || c.registers[0] != 0x12345678abcdef00 || c.readMXCSR() != tc.status {
			t.Fatal("fault atomicity")
		}
	}
}
