package s390

import "fmt"

// The 7201-02 DIAG I2 field drives two SCI control lines. They swap the
// high-order BSM address and the odd/even select (FETOM figure 2-65).
type interleave9020 byte

const (
	defeatInterleave9020  interleave9020 = 0x80
	reverseInterleave9020 interleave9020 = 0x40
	interleaveMask9020                   = defeatInterleave9020 | reverseInterleave9020
	oddBank9020           uint32         = 1 << 3
	highBSM9020           uint32         = 1 << 17
)

func (mode interleave9020) physical(addr uint32) uint32 {
	if mode == 0 || addr == ^uint32(0) {
		return addr
	}
	addr = addr&^(oddBank9020|highBSM9020) | (addr&oddBank9020)<<14 | (addr&highBSM9020)>>14
	if mode&reverseInterleave9020 != 0 {
		addr ^= oddBank9020
	}
	return addr
}

func (c *CPU) setInterleave9020(mode interleave9020) {
	if c.maintenance9020.interleave == mode {
		return
	}
	c.maintenance9020.interleave = mode
	c.ipageValid = false
}

func (c *CPU) interleaveMode9020() interleave9020 {
	if c.interleavePanel9020 != 0 && c.stateZero9020() {
		return c.interleavePanel9020
	}
	return c.maintenance9020.interleave
}

// SetInterleavePanel9020 selects the 7201-02 CE's physical DEFEAT
// INTERLEAVING switch position. Call between Run calls.
func (m *Machine) SetInterleavePanel9020(cpu int, position string) error {
	if !m.Model9020 || m.cfg.Model9020A || m.cfg.IOCE || cpu < 0 || cpu >= len(m.CPUs) || m.CPUs[cpu].Addr >= 4 {
		return fmt.Errorf("9020 interleave switch: CPU %d is not a 7201-02 CE", cpu)
	}
	var mode interleave9020
	switch position {
	case "PROC":
	case "NO REV":
		mode = defeatInterleave9020
	case "REV":
		mode = reverseInterleave9020
	default:
		return fmt.Errorf("9020 interleave switch: invalid position %q", position)
	}
	c := m.CPUs[cpu]
	c.interleavePanel9020 = mode
	c.ipageValid = false
	return nil
}

func (m *Machine) interleavingDefeated9020() bool {
	if m.Model9020 {
		for _, c := range m.CPUs {
			if c.interleaveMode9020() != 0 {
				return true
			}
		}
	}
	return false
}

// The SE transposes the IOCE storage-address bus when a connected CE
// asserts either distributed control line (D22A4500 statements 151–183).
func (s *ChannelSubsystem) ioceInterleave9020(absolute uint32) interleave9020 {
	if !s.m.Model9020 || s.m.isDisplayAddress9020(absolute) || s.machAddress(absolute) {
		return 0
	}
	se := absolute / s.m.storageElementSize9020()
	if se >= uint32(s.m.storageSlots9020()) {
		return 0
	}
	var mode interleave9020
	for _, c := range s.m.CPUs {
		if selected := c.interleaveMode9020(); c.Addr < 4 && selected != 0 && s.m.configurationListens9020(8+se, 20+uint32(c.Addr)) {
			mode |= selected
		}
	}
	return mode
}

func (c *CPU) setTimerInhibit9020(inhibit bool) {
	state := &c.maintenance9020
	if inhibit && state.timerInhibitSince == 0 {
		c.intervalTimer()
		state.timerInhibitSince = c.M.tod
	} else if !inhibit && state.timerInhibitSince != 0 {
		c.itBase += c.M.tod - state.timerInhibitSince
		state.timerInhibitSince = 0
	}
}
