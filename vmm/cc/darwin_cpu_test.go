package cc

import (
	"j5.nz/cc/hypervisor/x86state"
	"testing"
)

func TestDarwinCPUTruthfulVirtualProcessor(t *testing.T) {
	c := &cpuidTestCPU{input: []x86state.CPUIDEntry{
		{Function: 0, Eax: 32},
		{Function: 1, Ecx: 1<<9 | 1<<26, Edx: 1<<4 | 1<<28, Ebx: 0xff080800},
		{Function: 4, Eax: 1 | 7<<26 | 3<<14},
		{Function: 7, Ebx: 0xffffffff},
		{Function: 0x80000000, Eax: 0x80000020},
		{Function: 0x80000001, Edx: 1 << 29},
	}}
	if err := configureDarwinCPU(c); err != nil {
		t.Fatal(err)
	}
	for _, e := range c.output {
		switch e.Function {
		case 1:
			if e.Eax != 0x10676 || e.Ecx != 1<<9|1<<31 || e.Edx != 1<<4 || e.Ebx>>16 != 1 {
				t.Fatalf("wrong virtual CPU %#v", e)
			}
		case 4:
			if e.Eax != 1 {
				t.Fatalf("invented cache topology %#v", e)
			}
		case 5, 6, 7, 8, 9, 0xa:
			if e.Eax != 0 || e.Ebx != 0 || e.Ecx != 0 || e.Edx != 0 {
				t.Fatal("unconfigured feature or PMU exposed")
			}
		}
	}
	// Missing accelerator prerequisites must fail before applying a profile.
	for _, fn := range []uint32{4, 0x80000001} {
		bad := &cpuidTestCPU{}
		for _, e := range c.input {
			if e.Function != fn {
				bad.input = append(bad.input, e)
			}
		}
		if configureDarwinCPU(bad) == nil || bad.output != nil {
			t.Fatal("accepted missing long mode/cache")
		}
	}
}

// A missing out-of-range PMU leaf is not equivalent to a zero PMU response:
// Intel/KVM can fall back to the highest basic leaf's cache geometry.
func TestDarwinCPUNoPhantomPerformanceCounters(t *testing.T) {
	c := &cpuidTestCPU{input: []x86state.CPUIDEntry{
		{Function: 0, Eax: 0x20},
		{Function: 1, Ecx: 0xffffffff, Edx: 0xffffffff},
		{Function: 4, Eax: 0x3c004121, Ebx: 0x01c0003f, Edx: 7},
		{Function: 5, Eax: 64, Ebx: 64, Ecx: 3, Edx: 0x20},
		{Function: 7, Ebx: 0xffffffff},
		{Function: 0xa, Eax: 0x07300405, Ebx: 0, Ecx: 0, Edx: 0x00008603},
		{Function: 0x80000000, Eax: 0x80000008},
		{Function: 0x80000001, Edx: 1 << 29},
	}}
	if err := configureDarwinCPU(c); err != nil {
		t.Fatal(err)
	}
	seen := map[uint32]int{}
	for _, e := range c.output {
		seen[e.Function]++
		if e.Function == 0 && e.Eax != 0xa {
			t.Fatalf("PMU leaf out of range: %#v", e)
		}
		if e.Function >= 5 && e.Function <= 0xa && (e.Index != 0 || e.Flags != 0 || e.Eax != 0 || e.Ebx != 0 || e.Ecx != 0 || e.Edx != 0) {
			t.Fatalf("phantom backend feature: %#v", e)
		}
	}
	for f := uint32(5); f <= 0xa; f++ {
		if seen[f] != 1 {
			t.Fatalf("leaf %#x appears %d times", f, seen[f])
		}
	}
}
