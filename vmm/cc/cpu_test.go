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

func TestFourCoreCPUIDTopology(t *testing.T) {
	for id := 0; id < 4; id++ {
		c := &cpuidTestCPU{input: []x86state.CPUIDEntry{
			{Function: 0, Eax: 32}, {Function: 1, Ebx: 0xffffffff, Edx: 0xffffffff},
			{Function: 4, Eax: 0xffffffff, Ebx: 63, Ecx: 63},
			{Function: 0xb, Index: 0, Ebx: 128, Edx: 99},
			{Function: 0x80000001, Edx: 1 << 29},
		}}
		if err := configureCPUTopology(c, true, id, 4); err != nil {
			t.Fatal(err)
		}
		seen := map[uint32]int{}
		for _, e := range c.output {
			seen[e.Function]++
			switch e.Function {
			case 0:
				if e.Eax != 0xb {
					t.Fatal("topology leaf inaccessible")
				}
			case 1:
				if e.Ebx>>24 != uint32(id) || e.Ebx>>16&255 != 4 || e.Edx&(1<<28) == 0 {
					t.Fatalf("wrong package/APIC identity: %+v", e)
				}
			case 4:
				if e.Eax>>26 != 3 || e.Eax>>14&0xfff != 0 {
					t.Fatal("host cache sharing topology leaked")
				}
			case 0xb:
				if e.Edx != uint32(id) || e.Flags != 1 {
					t.Fatal("wrong extended topology ID")
				}
				if e.Index == 0 && (e.Eax != 0 || e.Ebx != 1 || e.Ecx != 0x100) {
					t.Fatal("unexpected SMT")
				}
				if e.Index == 1 && (e.Eax != 2 || e.Ebx != 4 || e.Ecx != 0x201) {
					t.Fatal("not one four-core package")
				}
				if e.Index == 2 && e.Ebx != 0 {
					t.Fatal("missing terminator")
				}
			}
		}
		if seen[1] != 1 || seen[4] != 1 || seen[0xb] != 3 {
			t.Fatal("missing/duplicate topology leaves", seen)
		}
	}
}

type fallbackTestCPU struct {
	cpuidTestCPU
	values map[uint32]uint64
}

func (c *fallbackTestCPU) SetReadOnlyFallbackMSRs(values map[uint32]uint64) error {
	c.values = values
	return nil
}
func TestAMDPortableSMPFeatureControl(t *testing.T) {
	c := &fallbackTestCPU{cpuidTestCPU: cpuidTestCPU{input: []x86state.CPUIDEntry{
		{Function: 0, Eax: 0x10, Ebx: 0x68747541, Edx: 0x69746e65, Ecx: 0x444d4163},
		{Function: 1, Ecx: 0xffffffff, Edx: 0xffffffff},
		{Function: 0x80000001, Edx: 1 << 29},
	}}}
	if err := configureCPUTopology(c, true, 0, 4); err != nil {
		t.Fatal(err)
	}
	if len(c.values) != 1 || c.values[0x3a] != 1 {
		t.Fatalf("unsafe FEATURE_CONTROL policy: %v", c.values)
	}
	topology := false
	for _, e := range c.output {
		if e.Function == 0 && e.Eax != 0xb {
			t.Fatal("lost topology leaf range")
		}
		if e.Function == 1 && e.Ecx&(1<<5) != 0 {
			t.Fatal("VMX exposed with disabled FEATURE_CONTROL")
		}
		if e.Function == 0xb && e.Index == 1 && e.Ebx == 4 {
			topology = true
		}
	}
	if !topology {
		t.Fatal("lost SMP topology")
	}
	unsupported := &cpuidTestCPU{input: c.input}
	if err := configureCPUTopology(unsupported, true, 0, 4); err == nil {
		t.Fatal("silently accepted missing accelerator MSR support")
	}
	if err := configureCPUTopology(unsupported, true, 1, 4); err != nil {
		t.Fatal("AP must reuse machine-owner policy:", err)
	}
}
