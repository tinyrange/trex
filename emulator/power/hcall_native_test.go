package power

import (
	"encoding/binary"
	"testing"
)

// TestNativeHypercalls checks declarative responses and their fallback to
// the scripted handler outside the declared contract.
func TestNativeHypercalls(t *testing.T) {
	m := NewMachine(Config{Memory: 1 << 20, MIPS: 100})
	m.StopAllInterrupts = false
	scripted := 0
	m.Hypercall = func(c *CPU) error { scripted++; c.GPR[3] = 99; return nil }
	const fill, cede = 0x1001, 0x1002
	if err := m.SetNativeHypercall(fill, &NativeHypercall{GPRs: []RegisterValue{{3, 0}},
		ZeroFill: &ZeroFill{Address: 5, Length: 6, AddressMask: 1<<60 - 1, Align: 4, Limit: 256}}); err != nil {
		t.Fatal(err)
	}
	if err := m.SetNativeHypercall(cede, &NativeHypercall{GPRs: []RegisterValue{{3, 0}}, MSRSet: MSREE, Wait: true, ScriptEvery: 3}); err != nil {
		t.Fatal(err)
	}
	c := m.CPUs[0]
	sc := func(token, r5, r6 uint64) {
		binary.BigEndian.PutUint32(m.Mem[0x1000:], 0x44000022) // sc 1
		c.PC, c.MSR, c.Waiting = 0x1000, MSRSF|MSRME, false
		c.GPR[3], c.GPR[5], c.GPR[6] = token, r5, r6
		if r := c.Step(); r != nil {
			t.Fatalf("stop %v", r)
		}
	}
	copy(m.Mem[0x4000:], "abcdefgh")
	sc(fill, 1<<63|0x4000, 7)
	if c.GPR[3] != 0 || string(m.Mem[0x4000:0x4008]) != "\x00\x00\x00\x00efgh" || scripted != 0 || c.PC != 0x1004 {
		t.Fatalf("zero fill: r3 %d memory %q scripted %d pc %x", c.GPR[3], m.Mem[0x4000:0x4008], scripted, c.PC)
	}
	sc(fill, 0x4000, 512) // over the limit: the script decides
	if c.GPR[3] != 99 || scripted != 1 {
		t.Fatalf("limit fallback: r3 %d scripted %d", c.GPR[3], scripted)
	}
	sc(cede, 0, 0)
	if c.GPR[3] != 0 || c.MSR&MSREE == 0 || !c.Waiting || scripted != 1 {
		t.Fatalf("cede: r3 %d msr %x waiting %v scripted %d", c.GPR[3], c.MSR, c.Waiting, scripted)
	}
	sc(cede, 0, 0)
	sc(cede, 0, 0) // every third call is scripted
	if scripted != 2 {
		t.Fatalf("script_every: scripted %d", scripted)
	}
	if got := m.HypercallCounts(); got[fill] != 2 || got[cede] != 3 {
		t.Fatalf("counts %v", got)
	}
}

func TestNativeHypercallWake(t *testing.T) {
	m := NewMachine(Config{Memory: 1 << 20, CPUs: 4, MIPS: 100})
	m.StopAllInterrupts = false
	const prod = 0x1003
	scripted := 0
	m.Hypercall = func(c *CPU) error { scripted++; c.GPR[3] = 99; return nil }
	if err := m.SetNativeHypercall(prod, &NativeHypercall{GPRs: []RegisterValue{{3, 0}}, Wake: &WakeCPU{Index: 4, Limit: 3}}); err != nil {
		t.Fatal(err)
	}
	c, target := m.CPUs[0], m.CPUs[2]
	sc := func(index uint64) {
		binary.BigEndian.PutUint32(m.Mem[0x1000:], 0x44000022) // sc 1
		c.PC, c.MSR = 0x1000, MSRSF|MSRME
		c.GPR[3], c.GPR[4] = prod, index
		if r := c.Step(); r != nil {
			t.Fatalf("stop %v", r)
		}
	}
	target.Waiting = true
	sc(2)
	if target.Waiting || c.GPR[3] != 0 || scripted != 0 {
		t.Fatalf("native wake: waiting %v r3 %x scripted %d", target.Waiting, c.GPR[3], scripted)
	}
	target.Waiting = true
	sc(3) // beyond the declared limit: the script decides
	if scripted != 1 || c.GPR[3] != 99 || !target.Waiting {
		t.Fatalf("out-of-contract wake: scripted %d r3 %x", scripted, c.GPR[3])
	}
	if err := m.SetNativeHypercall(prod, &NativeHypercall{Wake: &WakeCPU{Index: 32}}); err == nil {
		t.Fatal("wake register 32 accepted")
	}
}
