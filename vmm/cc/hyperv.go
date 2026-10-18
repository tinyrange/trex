package cc

import (
	"j5.nz/cc/hypervisor"
	"j5.nz/cc/hypervisor/x86state"
)

// Offer kernel-owned clocks and, after activation, synthetic timers.
// VMBus, reset, crash and nested virtualization are deliberately not exposed.
func hyperVClockCPUID(cpu hypervisor.X86) ([]x86state.CPUIDEntry, error) {
	hv, ok := cpu.(hypervisor.X86HyperV)
	if !ok {
		return nil, nil
	}
	supported, err := hv.SupportedHyperVCPUID()
	if err != nil {
		return nil, err
	}
	const clock = 1<<1 | 1<<5 | 1<<9 // reference counter, hypercall/OS ID, reference TSC
	var features x86state.CPUIDEntry
	for _, e := range supported {
		if e.Function == 0x40000003 {
			features = e
		}
	}
	if features.Eax&clock != clock {
		return nil, nil
	}
	eax, edx := uint32(clock), uint32(0)
	const timers = 1<<2 | 1<<3 | 1<<6 // SynIC, synthetic timers, VP index
	if features.Eax&timers == timers {
		if synic, ok := cpu.(hypervisor.X86HyperVSynIC); ok {
			enabled, err := synic.EnableHyperVSynIC()
			if err != nil {
				return nil, err
			}
			if enabled {
				eax |= timers
				edx = features.Edx & (1 << 19)
			} // optional direct mode
		}
	}
	return []x86state.CPUIDEntry{
		{Function: 0x40000000, Eax: 0x40000005, Ebx: 0x7263694d, Ecx: 0x666f736f, Edx: 0x76482074}, // Microsoft Hv
		{Function: 0x40000001, Eax: 0x31237648},                                                    // Hv#1
		{Function: 0x40000002, Eax: 0x3839, Ebx: 0x000a0000},
		{Function: 0x40000003, Eax: eax, Edx: edx},
		{Function: 0x40000004, Ebx: 0xffffffff}, // no spinlock notification recommendation
		{Function: 0x40000005, Eax: 4, Ebx: 4},
	}, nil
}
