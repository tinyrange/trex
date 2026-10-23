package amd64

import (
	"encoding/binary"
	"github.com/tinyrange/trex/emulator/cpu"
	"testing"
)

func TestCVTTSS2SI(t *testing.T) {
	for _, tc := range []struct {
		input        uint32
		wide         bool
		want, status uint64
	}{
		{0x3fe00000, false, 1, 32}, {0xbfe00000, false, 0xffffffff, 32},
		{0xbfe00000, true, 0xffffffffffffffff, 32},
		{0xcf000000, false, 0x80000000, 0}, {0x4f000000, false, 0x80000000, 1},
		{0x4f000000, true, 0x80000000, 0},
		{0xdf000000, true, 0x8000000000000000, 0}, {0x5f000000, true, 0x8000000000000000, 1},
		{0x7fc00000, true, 0x8000000000000000, 1},
		{0x7f800000, false, 0x80000000, 1}, {1, true, 0, 32},
	} {
		for _, memory := range []bool{false, true} {
			code := "f30f2cc8"
			if tc.wide {
				code = "f3480f2cc8"
			}
			if memory {
				code = code[:len(code)-2] + "0a"
			}
			c, m := codeMemory(t, code)
			binary.LittleEndian.PutUint32(c.xmm[0][:4], tc.input)
			c.registers[1] = 0xaaaaaaaaaaaaaaaa
			c.registers[2] = 0x200000003
			if err := m.Map(c.registers[2], c.xmm[0][:4], cpu.Read); err != nil {
				t.Fatal(err)
			}
			c.setMXCSR(0x7f80)
			c.flags = flagCarry
			before := c.xmm
			if _, err := c.Step(m); err != nil {
				t.Fatal(err)
			}
			if c.registers[1] != tc.want || c.readMXCSR() != 0x7f80|tc.status || c.flags != flagCarry || c.xmm != before {
				t.Fatalf("%s input%x got%x want%x MXCSR%x", code, tc.input, c.registers[1], tc.want, c.readMXCSR())
			}
		}
	}
}
func TestCVTTSS2SIFaultAndDAZ(t *testing.T) {
	for _, tc := range []struct {
		input   uint32
		control uint64
		fault   bool
		status  uint64
	}{
		{0x7fc00000, 0x1f00, true, 1}, {0x3fe00000, 0xf80, true, 32}, {1, 0x1fc0, false, 0},
	} {
		c, m := codeMemory(t, "f3480f2cc8")
		binary.LittleEndian.PutUint32(c.xmm[0][:4], tc.input)
		c.registers[1] = 42
		c.setMXCSR(tc.control)
		pc := c.PC()
		_, err := c.Step(m)
		if (err != nil) != tc.fault {
			t.Fatal(err)
		}
		if tc.fault && (c.registers[1] != 42 || c.PC() != pc) {
			t.Fatal("fault changed destination/PC")
		}
		if !tc.fault && c.registers[1] != 0 {
			t.Fatal("DAZ")
		}
		if c.readMXCSR() != tc.control|tc.status {
			t.Fatal("MXCSR")
		}
	}
}
