package amd64

import "testing"

func TestRDTSCInstructionClockAndClone(t *testing.T) {
	c, m := codeMemory(t, "0f 31 90 0f 31")
	start := c.rip
	c.registers[0], c.registers[2] = ^uint64(0), ^uint64(0)
	c.registers[1] = 0x123456789abcdef0
	flags := uint64(flagCarry | flagZero | flagOverflow)
	c.flags = flags
	if _, err := c.Step(m); err != nil {
		t.Fatal(err)
	}
	if c.registers[0] != 1 || c.registers[2] != 0 || c.flags != flags || c.registers[1] != 0x123456789abcdef0 {
		t.Fatalf("first timestamp/flags: eax=%#x edx=%#x rcx=%#x flags=%#x", c.registers[0], c.registers[2], c.registers[1], c.flags)
	}
	if c.rip != start+2 {
		t.Fatalf("RDTSC RIP = %#x, want %#x", c.rip, start+2)
	}
	if _, err := c.Step(m); err != nil { // NOP also advances the virtual clock.
		t.Fatal(err)
	}
	checkpoint := c.Clone().(*CPU)
	if _, err := c.Step(m); err != nil {
		t.Fatal(err)
	}
	if c.registers[0] != 3 || c.registers[2] != 0 {
		t.Fatalf("second timestamp = %#x:%#x", c.registers[2], c.registers[0])
	}
	if _, err := checkpoint.Step(m); err != nil {
		t.Fatal(err)
	}
	if checkpoint.registers != c.registers || checkpoint.flags != c.flags || checkpoint.timestampCounter != c.timestampCounter {
		t.Fatal("checkpoint replay changed the instruction clock")
	}
	c.rip = start
	c.timestampCounter = 0xffffffff
	c.registers[0], c.registers[2] = ^uint64(0), ^uint64(0)
	if _, err := c.Step(m); err != nil {
		t.Fatal(err)
	}
	if c.registers[0] != 0 || c.registers[2] != 1 || c.flags != flags {
		t.Fatalf("rollover timestamp = %#x:%#x, flags=%#x", c.registers[2], c.registers[0], c.flags)
	}
	if checkpoint.timestampCounter != 3 {
		t.Fatal("advancing the original changed its clone")
	}
}
