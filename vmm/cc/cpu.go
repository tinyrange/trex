package cc

import (
	"encoding/binary"
	"fmt"
	"math/bits"

	"j5.nz/cc/hypervisor"
	"j5.nz/cc/hypervisor/x86state"
)

// The legacy PC advertises the basic CPUID leaves understood by early protected
// mode guests. Accelerator-specific hypervisor/topology leaves are unnecessary
// for this single-CPU machine.
func configureCPU(cpu hypervisor.X86) error {
	return configureCPUArchitecture(cpu, false)
}

func configureCPUArchitecture(cpu hypervisor.X86, longMode bool) error {
	return configureCPUTopology(cpu, longMode, 0, 1)
}

func configureCPUTopology(cpu hypervisor.X86, longMode bool, id, count int) error {
	if count < 1 || count > 4 || id < 0 || id >= count {
		return fmt.Errorf("invalid PC CPU topology")
	}
	entries, err := cpu.SupportedCPUID()
	if err != nil {
		return err
	}
	// With SMP topology, the portable Intel identity has a basic leaf range
	// including leaf 7. Windows then reads FEATURE_CONTROL even without VMX.
	// AMD KVM does not implement this Intel-only register.
	// Keep the real topology; supply a locked, VMX/SGX-disabled read instead
	// of relaxing host-wide MSR handling or patching the guest loader.
	if longMode && count > 1 && id == 0 {
		for _, entry := range entries {
			if entry.Function == 0 && entry.Ebx == 0x68747541 && entry.Edx == 0x69746e65 && entry.Ecx == 0x444d4163 {
				fallback, ok := cpu.(hypervisor.X86ReadOnlyFallbackMSRs)
				if !ok {
					return fmt.Errorf("AMD Intel-compatible CPU requires read-only MSR fallback")
				}
				if err := fallback.SetReadOnlyFallbackMSRs(map[uint32]uint64{0x3a: 1}); err != nil {
					return err
				}
			}
		}
	}
	var hvEntries []x86state.CPUIDEntry
	if longMode {
		hvEntries, err = hyperVClockCPUID(cpu)
		if err != nil {
			return err
		}
	}
	filtered := entries[:0]
	hasLongMode := false
	for _, entry := range entries {
		if entry.Function > 3 && !(count > 1 && entry.Function == 4) && !(longMode && entry.Function >= 0x80000000 && entry.Function <= 0x80000008) {
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
			if count > 1 {
				entry.Eax = 0xb
			}
			// A portable PC identity must not change with the accelerator's
			// host CPU. Guest image recipes can preinstall this processor.
			entry.Ebx, entry.Edx, entry.Ecx = 0x756e6547, 0x49656e69, 0x6c65746e // GenuineIntel
		}
		if entry.Function == 1 {
			entry.Eax = 0x663 // Family 6, model 6, stepping 3.
			// No XSAVE/AVX without their later enumeration leaves. Topology
			// describes one package with no SMT. AMD64 guests may use the
			// SSE4 instruction family and 16-byte atomic operations.
			if longMode {
				entry.Ecx &= 1<<0 | 1<<9 | 1<<13 | 1<<19 | 1<<20 | 1<<23 // SSE3, SSSE3, CX16, SSE4.1/4.2, POPCNT.
			} else {
				entry.Ecx = 0
			}
			entry.Ebx = entry.Ebx&0xffff | uint32(count)<<16 | uint32(id)<<24
			entry.Edx &= (1 << 27) - 1
			if count > 1 {
				entry.Edx |= 1 << 28
			}
		}
		if entry.Function == 4 && entry.Eax&31 != 0 {
			entry.Eax = entry.Eax&0x3fff | uint32(count-1)<<26
		}
		filtered = append(filtered, entry)
	}
	if longMode && !hasLongMode {
		return fmt.Errorf("cc x86_64 requires accelerator long-mode support")
	}
	if count > 1 {
		filtered = append(filtered,
			x86state.CPUIDEntry{Function: 0xb, Index: 0, Flags: 1, Eax: 0, Ebx: 1, Ecx: 1 << 8, Edx: uint32(id)},
			x86state.CPUIDEntry{Function: 0xb, Index: 1, Flags: 1, Eax: uint32(bits.Len(uint(count - 1))), Ebx: uint32(count), Ecx: 2<<8 | 1, Edx: uint32(id)},
			x86state.CPUIDEntry{Function: 0xb, Index: 2, Flags: 1, Ecx: 2, Edx: uint32(id)})
	}
	if len(hvEntries) != 0 {
		for i := range filtered {
			if filtered[i].Function == 1 {
				filtered[i].Ecx |= 1 << 31
			}
		}
		filtered = append(filtered, hvEntries...)
	}
	return cpu.SetCPUID(filtered)
}
