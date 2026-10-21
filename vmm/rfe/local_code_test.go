package rfe

import (
	"testing"
)

func finishLocalCode(t *testing.T, c *cpu, pc uint64) {
	t.Helper()
	c.pending = nil
	c.core.PC = pc
	c.core.R[1] = 256
	for i := 0; i < 10000 && c.pending == nil; i++ {
		if err := c.jit.Run(4096); err != nil {
			t.Fatal(err)
		}
	}
	if c.pending == nil {
		t.Fatal("local code did not reach port")
	}
}
func TestCodeMutationPreservesUnrelatedSamePageNativeLink(t *testing.T) {
	code := []byte{0x40, 0x49, 0x75, 0xfc, 0xe6, 0xf2}
	actual := jitCPU(t, 16, code)
	copy(actual.ram[0x5200:], code)
	finishLocalCode(t, actual, 0x1000)
	finishLocalCode(t, actual, 0x1200)
	m := actual.jit.NativeContext()
	first, second := m.LookupLink(0x5000), m.LookupLink(0x5200)
	if first == nil || second == nil {
		t.Fatal("both same-page loops must be published before mutation")
	}
	entry := second.Entry
	actual.BeforeRAMWrite(0x5000, 1)
	actual.ram[0x5000] = 0x43 // INC BX, formerly INC AX
	if m.LookupLink(0x5000) != nil {
		t.Fatal("modified native publication survived")
	}
	if link := m.LookupLink(0x5200); link == nil || link.Entry != entry {
		t.Fatal("unrelated same-page native code was invalidated")
	}
	actual.pending = nil
	actual.core.PC = 0x1000
	actual.core.R[1] = 256
	expected := jitCPU(t, 16, code)
	copy(expected.ram, actual.ram)
	expected.core.R, expected.core.PC, expected.core.Flags, expected.core.Retired = actual.core.R, actual.core.PC, actual.core.Flags, actual.core.Retired
	expected.system.TSC = actual.system.TSC
	referenceToPort(t, expected)
	for i := 0; i < 10000 && actual.pending == nil; i++ {
		if err := actual.jit.Run(4096); err != nil {
			t.Fatal(err)
		}
	}
	if actual.pending == nil {
		t.Fatal("modified loop did not finish")
	}
	equalJITState(t, actual, expected)
}
