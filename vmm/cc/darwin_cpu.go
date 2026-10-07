package cc

import (
	"fmt"
	"j5.nz/cc/hypervisor"
)

// Penryn is an XNU-supported family that does not require newer topology or
// XSAVE state. Features remain intersected with accelerator support.
func configureDarwinCPU(cpu hypervisor.X86) error {
	entries, err := cpu.SupportedCPUID()
	if err != nil {
		return err
	}
	filtered := entries[:0]
	longMode, cache := false, false
	for _, e := range entries {
		if e.Function > 4 && (e.Function < 0x80000000 || e.Function > 0x80000008) {
			continue
		}
		switch e.Function {
		case 0:
			e.Eax = 4
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
	return cpu.SetCPUID(filtered)
}
