package cc

import (
	"encoding/binary"
	"testing"

	"j5.nz/cc/hypervisor"
	"j5.nz/cc/hypervisor/x86state"
)

type cpuidTestCPU struct {
	hypervisor.X86
	input, output []x86state.CPUIDEntry
}

func (c *cpuidTestCPU) SupportedCPUID() ([]x86state.CPUIDEntry, error) {
	return append([]x86state.CPUIDEntry(nil), c.input...), nil
}
func (c *cpuidTestCPU) SetCPUID(entries []x86state.CPUIDEntry) error { c.output = entries; return nil }

func TestPortableCPUIdentity(t *testing.T) {
	for _, longMode := range []bool{false, true} {
		c := &cpuidTestCPU{input: []x86state.CPUIDEntry{
			{Function: 0, Eax: 32, Ebx: 1, Ecx: 2, Edx: 3},
			{Function: 1, Eax: 0x00abcdef, Ebx: 0xffffffff, Ecx: 0xffffffff, Edx: 0xffffffff},
			{Function: 7, Eax: 1234},
			{Function: 0x80000000, Eax: 0x80000020},
			{Function: 0x80000001, Ecx: 0xffffffff, Edx: 0xffffffff},
			{Function: 0x80000002, Eax: 0xdeadbeef},
			{Function: 0x80000003, Eax: 0xdeadbeef},
			{Function: 0x80000004, Eax: 0xdeadbeef},
		}}
		if err := configureCPUArchitecture(c, longMode); err != nil {
			t.Fatal(err)
		}
		var brand []byte
		for _, e := range c.output {
			switch e.Function {
			case 0:
				if e.Eax != 3 || e.Ebx != 0x756e6547 || e.Edx != 0x49656e69 || e.Ecx != 0x6c65746e {
					t.Fatal("unstable vendor or leaf limit")
				}
			case 1:
				var ecx uint32
				if longMode {
					ecx = 1<<0 | 1<<9 | 1<<13 | 1<<19 | 1<<20 | 1<<23
				}
				if e.Eax != 0x663 || e.Ecx != ecx || e.Ebx>>16 != 1 || e.Edx>>27 != 0 {
					t.Fatal("unstable signature or unsupported topology/features")
				}
			case 7:
				t.Fatal("unconfigured feature leaf exposed")
			case 0x80000002, 0x80000003, 0x80000004:
				for _, v := range []uint32{e.Eax, e.Ebx, e.Ecx, e.Edx} {
					brand = binary.LittleEndian.AppendUint32(brand, v)
				}
			}
			if !longMode && e.Function >= 0x80000000 {
				t.Fatal("legacy extended leaf policy changed")
			}
		}
		if longMode && (len(brand) != 48 || string(brand[:len("TinyRangeX Virtual CPU")]) != "TinyRangeX Virtual CPU") {
			t.Fatalf("unstable brand %q", brand)
		}
	}
}

func TestLongModeDoesNotInventInstructionFeatures(t *testing.T) {
	c := &cpuidTestCPU{input: []x86state.CPUIDEntry{
		{Function: 0, Eax: 3},
		{Function: 1, Ecx: 1 << 13},
		{Function: 0x80000001, Edx: 1 << 29},
	}}
	if err := configureCPUArchitecture(c, true); err != nil {
		t.Fatal(err)
	}
	for _, entry := range c.output {
		if entry.Function == 1 && entry.Ecx != 1<<13 {
			t.Fatalf("advertised unavailable accelerator instructions: %#x", entry.Ecx)
		}
	}
}
