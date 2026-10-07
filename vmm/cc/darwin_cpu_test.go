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
		case 7:
			t.Fatal("unconfigured feature leaf exposed")
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
