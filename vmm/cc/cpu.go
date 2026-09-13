package cc

import "j5.nz/cc/hypervisor"

// The legacy PC advertises the basic CPUID leaves understood by early protected
// mode guests. Accelerator-specific hypervisor/topology leaves are unnecessary
// for this single-CPU machine.
func configureCPU(cpu hypervisor.X86) error {
	entries, err := cpu.SupportedCPUID()
	if err != nil {
		return err
	}
	filtered := entries[:0]
	for _, entry := range entries {
		if entry.Function > 3 {
			continue
		}
		if entry.Function == 0 {
			entry.Eax = min(entry.Eax, 3)
		}
		if entry.Function == 1 {
			// No XSAVE/AVX without their later enumeration leaves. One logical
			// CPU, APIC ID zero, and no SMT or post-SSE2 feature advertisement.
			entry.Ecx = 0
			entry.Ebx = entry.Ebx&0xffff | 1<<16
			entry.Edx &= (1 << 27) - 1
		}
		filtered = append(filtered, entry)
	}
	return cpu.SetCPUID(filtered)
}
