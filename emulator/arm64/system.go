package arm64

import (
	"fmt"
	"strings"
)

// System register values are explicit state, rather than fabricated at MRS sites.
var systemRegisters = []struct {
	name     string
	encoding uint32
}{
	{"sctlr_el1", 0xc080}, {"ttbr0_el1", 0xc100}, {"ttbr1_el1", 0xc101},
	{"tcr_el1", 0xc102}, {"mair_el1", 0xc510}, {"vbar_el1", 0xc600},
	{"cpacr_el1", 0xc082}, {"tpidr_el0", 0xde82}, {"tpidrro_el0", 0xde83}, {"tpidr_el1", 0xc684},
	{"par_el1", 0xc3a0},
	{"id_aa64isar0_el1", 0xc030}, {"id_aa64isar1_el1", 0xc031}, {"id_aa64isar2_el1", 0xc032},
	{"id_aa64pfr0_el1", 0xc020}, {"id_aa64pfr1_el1", 0xc021}, {"id_aa64dfr0_el1", 0xc028},
	{"id_aa64mmfr0_el1", 0xc038}, {"midr_el1", 0xc000}, {"mpidr_el1", 0xc005},
	{"ctr_el0", 0xd801}, {"dczid_el0", 0xd807},
	{"id_aa64mmfr1_el1", 0xc039}, {"id_aa64mmfr2_el1", 0xc03a},
}

func systemIndex(name string) int {
	for j, r := range systemRegisters {
		if r.name == name {
			return j
		}
	}
	return -1
}
func (c *CPU) systemInstruction(i uint32) (bool, error) {
	encoding := i >> 5 & 0xffff
	read := i>>21&1 != 0
	rd := i & 31
	if encoding >= 0xdf00 && encoding <= 0xdf02 {
		name := []string{"cntfrq_el0", "cntpct_el0", "cntvct_el0"}[encoding-0xdf00]
		if read {
			v, _ := c.Register(name)
			c.w(rd, v, 64, false)
		} else if encoding == 0xdf00 {
			return true, c.SetRegister(name, c.r(rd, false))
		} else {
			return true, fmt.Errorf("arm64: write to read-only %s", name)
		}
		return true, nil
	}
	name := ""
	switch encoding {
	case 0xc4f1:
		name = "pmintenset_el1"
	case 0xc4f2:
		name = "pmintenclr_el1"
	case 0xdf7f:
		name = "pmccfiltr_el0"
	case 0xdcf0:
		name = "pmuserenr_el0"
	}
	if name != "" {
		if read {
			v, _ := c.Register(name)
			c.w(rd, v, 64, false)
		} else {
			return true, c.SetRegister(name, c.r(rd, false))
		}
		return true, nil
	}
	if encoding >= 0xdce0 && encoding <= 0xdce3 {
		name := []string{"pmcr_el0", "pmcntenset_el0", "pmcntenclr_el0", "pmovsclr_el0"}[encoding-0xdce0]
		if read {
			v, _ := c.Register(name)
			c.w(rd, v, 64, false)
		} else {
			return true, c.SetRegister(name, c.r(rd, false))
		}
		return true, nil
	}
	if encoding == 0xdce8 { // Deterministic counter: one tick per completed instruction.
		if read {
			c.w(rd, c.cycles, 64, false)
		} else {
			c.cycles = c.r(rd, false)
		}
		return true, nil
	}
	if encoding == 0xda10 {
		if read {
			c.w(rd, c.nzcv, 64, false)
		} else {
			c.nzcv = c.r(rd, false) & 0xf0000000
		}
		return true, nil
	}
	if encoding == 0xda11 {
		if c.currentEL == 0 {
			return true, fmt.Errorf("arm64: DAIF access at EL0")
		}
		if read {
			c.w(rd, c.daif, 64, false)
		} else {
			c.daif = c.r(rd, false) & 0x3c0
		}
		return true, nil
	}
	for j, r := range systemRegisters {
		if r.encoding == encoding {
			if c.currentEL == 0 && r.name != "tpidr_el0" && r.name != "tpidrro_el0" && r.name != "ctr_el0" && r.name != "dczid_el0" {
				return true, fmt.Errorf("arm64: %s access at EL0", r.name)
			}
			if read {
				c.w(rd, c.system[j], 64, false)
			} else {
				if strings.HasPrefix(r.name, "id_") || r.name == "midr_el1" || r.name == "mpidr_el1" || r.name == "ctr_el0" || r.name == "dczid_el0" {
					return true, fmt.Errorf("arm64: write to read-only %s", r.name)
				}
				c.system[j] = c.r(rd, false)
				if j <= 4 {
					c.ClearTranslationCache()
				}
			}
			return true, nil
		}
	}
	return false, nil
}
