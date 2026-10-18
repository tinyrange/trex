package cc

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/tinyrange/trex/emulator/cpu"
	"j5.nz/cc/hypervisor"
)

// tripleFaultDetail is called only after all CPU execution has stopped. Keep
// the observation bounded and read-only; KVM shutdown alone does not identify
// the first exception, and CR2 may describe an earlier page fault.
func (p *pc) tripleFaultDetail(core hypervisor.X86) string {
	var out strings.Builder
	out.WriteString("x86 triple fault")
	r, re := core.Registers()
	s, se := core.SystemRegisters()
	if re != nil {
		fmt.Fprintf(&out, "; registers unavailable: %v", re)
	} else {
		fmt.Fprintf(&out, "; rip=%#x rsp=%#x rflags=%#x rax=%#x rcx=%#x rdx=%#x", r.Rip, r.Rsp, r.Rflags, r.Rax, r.Rcx, r.Rdx)
	}
	if se != nil {
		fmt.Fprintf(&out, "; system registers unavailable: %v", se)
	} else {
		fmt.Fprintf(&out, "; cr0=%#x cr2=%#x cr3=%#x cr4=%#x efer=%#x cs=%#x cs.base=%#x cs.l=%d idt=%#x/%#x", s.Cr0, s.Cr2, s.Cr3, s.Cr4, s.Efer, s.Cs.Selector, s.Cs.Base, s.Cs.L, s.Idt.Base, s.Idt.Limit)
	}
	if re == nil && se == nil {
		address := r.Rip
		if s.Efer&(1<<10) == 0 || s.Cs.L == 0 {
			address += s.Cs.Base
		}
		var code [16]byte
		if err := (efiMemory{p: p, system: &s}).ReadMemory(address, code[:], cpu.Read); err != nil {
			fmt.Fprintf(&out, "; instruction bytes unavailable: %v", err)
		} else {
			fmt.Fprintf(&out, "; instruction_bytes=%x", code)
		}
	}
	fmt.Fprintf(&out, "; last_service=%q", p.lastService)
	// The bounded firmware history survives accelerator reset-on-shutdown.
	// Label it separately so none of these pre-fault PCs imply a fault site.
	if len(p.efiTrace) != 0 {
		if trace, err := json.Marshal(p.efiTrace); err == nil {
			fmt.Fprintf(&out, "; recent_efi=%s", trace)
		}
	}
	return out.String()
}
