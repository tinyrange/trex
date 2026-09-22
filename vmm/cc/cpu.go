package cc

import (
	"encoding/binary"
	"fmt"
	"j5.nz/cc/hypervisor"
)

// The legacy PC advertises the basic CPUID leaves understood by early protected
// mode guests. Accelerator-specific hypervisor/topology leaves are unnecessary
// for this single-CPU machine.
func configureCPU(cpu hypervisor.X86) error {
	return configureCPUArchitecture(cpu, false)
}

func configureCPUArchitecture(cpu hypervisor.X86, longMode bool) error {
	entries, err := cpu.SupportedCPUID()
	if err != nil {
		return err
	}
	filtered := entries[:0]
	hasLongMode := false
	for _, entry := range entries {
		if entry.Function > 3 && !(longMode && entry.Function >= 0x80000000 && entry.Function <= 0x80000008) {
			continue
		}
		if entry.Function == 0x80000000 {
			entry.Eax = min(entry.Eax, 0x80000008)
		}
		if entry.Function == 0x80000001 {
			// No SVM, topology extensions, or later vector extensions.
			entry.Ecx &= 1          // LAHF/SAHF in long mode.
			entry.Edx &= 0x2193fbff // Baseline x86, SYSCALL, NX, FXSR and long mode.
			hasLongMode = entry.Edx&(1<<29) != 0
		}
		if entry.Function >= 0x80000002 && entry.Function <= 0x80000004 {
			var brand [48]byte
			copy(brand[:], "TinyRangeX Virtual CPU")
			part := brand[(entry.Function-0x80000002)*16:]
			entry.Eax, entry.Ebx = binary.LittleEndian.Uint32(part), binary.LittleEndian.Uint32(part[4:])
			entry.Ecx, entry.Edx = binary.LittleEndian.Uint32(part[8:]), binary.LittleEndian.Uint32(part[12:])
		}
		if entry.Function == 0x80000007 {
			entry.Eax, entry.Ebx, entry.Ecx, entry.Edx = 0, 0, 0, entry.Edx&(1<<8)
		}
		if entry.Function == 0x80000008 {
			entry.Ebx, entry.Ecx, entry.Edx = 0, 0, 0
		}
		if entry.Function == 0 {
			entry.Eax = min(entry.Eax, 3)
			// A portable PC identity must not change with the accelerator's
			// host CPU. Guest image recipes can preinstall this processor.
			entry.Ebx, entry.Edx, entry.Ecx = 0x756e6547, 0x49656e69, 0x6c65746e // GenuineIntel
		}
		if entry.Function == 1 {
			entry.Eax = 0x663 // Family 6, model 6, stepping 3.
			// No XSAVE/AVX without their later enumeration leaves. One logical
			// CPU, APIC ID zero, and no SMT. AMD64 guests may use the
			// SSE4 instruction family and 16-byte atomic operations.
			if longMode {
				entry.Ecx &= 1<<0 | 1<<9 | 1<<13 | 1<<19 | 1<<20 | 1<<23 // SSE3, SSSE3, CX16, SSE4.1/4.2, POPCNT.
			} else {
				entry.Ecx = 0
			}
			entry.Ebx = entry.Ebx&0xffff | 1<<16
			entry.Edx &= (1 << 27) - 1
		}
		filtered = append(filtered, entry)
	}
	if longMode && !hasLongMode {
		return fmt.Errorf("cc x86_64 requires accelerator long-mode support")
	}
	return cpu.SetCPUID(filtered)
}
