package amd64

import (
	"github.com/tinyrange/trex/emulator/cpu"
	"testing"
)

func TestMFENCEOrdersMemoryWithoutClobber(t *testing.T) {
	c, m := codeMemory(t, "488901 0faef0 488b11 f4")
	const address = 0x200000000
	if err := m.Map(address, make([]byte, 8), cpu.Read|cpu.Write); err != nil {
		t.Fatal(err)
	}
	c.registers[0], c.registers[1] = 0x123456789abcdef0, address
	c.flags = flagCarry | flagZero
	runCode(t, c, m, 4)
	if c.registers[2] != c.registers[0] || c.flags != flagCarry|flagZero {
		t.Fatalf("rdx=%x flags=%x", c.registers[2], c.flags)
	}
}
