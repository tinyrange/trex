package cc

import (
	"fmt"
	"j5.nz/cc/hypervisor"
	"j5.nz/cc/hypervisor/x86state"
)

// Penryn is an XNU-supported family that does not require newer topology or
// XSAVE state. Features remain intersected with accelerator support.
func configureDarwinCPU(cpu hypervisor.X86) error {
	entries, err := cpu.SupportedCPUID()
	if err != nil {
		return err
	}
	filtered := make([]x86state.CPUIDEntry, 0, len(entries)+6)
	longMode, cache := false, false
	for _, e := range entries {
		if e.Function > 4 && (e.Function < 0x80000000 || e.Function > 0x80000008) {
			continue
		}
		switch e.Function {
		case 0:
			e.Eax = 0xa
			e.Ebx, e.Edx, e.Ecx = 0x756e6547, 0x49656e69, 0x6c65746e
		case 1:
			e.Eax = 0x10676
			e.Ebx = e.Ebx&0xffff | 1<<16
			// CPUID.HYPERVISOR identifies the virtual CPU without claiming any
			// extra instruction support. XNU's native power-management driver
			// uses it to select its virtual-processor implementation.
			e.Ecx &= 1<<0 | 1<<9 | 1<<13 | 1<<19 | 1<<31
			e.Ecx |= 1 << 31
			e.Edx &= (1 << 27) - 1
		case 4:
			e.Eax &= (1 << 14) - 1
			if e.Eax&31 != 0 {
				cache = true
			}
		case 0x80000000:
			e.Eax = min(e.Eax, 0x80000008)
		case 0x80000001:
			e.Ecx &= 1
			e.Edx &= 0x2193fbff
			longMode = e.Edx&(1<<29) != 0
		case 0x80000007:
			e.Eax, e.Ebx, e.Ecx = 0, 0, 0
			e.Edx &= 1 << 8
		case 0x80000008:
			e.Ebx, e.Ecx, e.Edx = 0, 0, 0
		}
		filtered = append(filtered, e)
	}
	if !longMode || !cache {
		return fmt.Errorf("cc Darwin requires accelerator long mode and deterministic cache enumeration")
	}
	// XNU4570 queries the architectural PMU leaf even on this Penryn profile.
	// An out-of-range basic CPUID query may return the highest basic leaf,
	// so omitting 0xa with max=4 can turn cache geometry into fake counters.
	// This machine supplies no virtual PMU. Enumerate through 0xa and return
	// explicit zero leaves for MONITOR/thermal/structured features and PMU,
	// rather than advertising unsupported counters or patching guest code.
	for function := uint32(5); function <= 0xa; function++ {
		filtered = append(filtered, x86state.CPUIDEntry{Function: function})
	}
	return cpu.SetCPUID(filtered)
}
