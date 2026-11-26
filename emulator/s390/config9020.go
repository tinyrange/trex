package s390

import (
	"fmt"
	"math/bits"
)

// A27-9020-01 Figure 8-2 uses the same bit for an element in the
// selection mask and in the configuration mask's communication field.
const (
	stateMask9020  = 0xc0000000
	scanMask9020   = 0x3c000000
	inhibitLOS9020 = 0x02000000
	seMask9020     = 0x00ffc000
	ceMask9020     = 0x00000f00
	ioceMask9020   = 0x00000007
	firstTCU9020   = 3
	lastTCU9020    = 5
	firstSCU9020   = 24
	lastSCU9020    = 26
	ioceMask9020E  = 0x00000006
)

type configRegister9020 struct {
	Word uint32
	Set  bool
}

func configurationBit9020(position uint32) uint32 {
	return uint32(0x80000000) >> position
}

func (m *Machine) installedElements9020() uint32 {
	var installed uint32
	for _, cpu := range m.CPUs {
		if cpu.Addr < 4 {
			installed |= configurationBit9020(20 + uint32(cpu.Addr))
		}
	}
	for i := range m.CPUs[0].storageElements9020() {
		installed |= configurationBit9020(8 + uint32(i))
	}
	if m.cfg.Model9020E {
		for i := range m.cfg.DisplayElements9020E {
			installed |= configurationBit9020(8 + max9020EStorageElements + uint32(i))
		}
	}
	for _, sub := range m.CSS.subs {
		if ioce := sub.devno >> 10; ioce < 3 {
			installed |= configurationBit9020(29 + uint32(ioce))
		}
		if sub.controller9020 != 0 {
			installed |= configurationBit9020(uint32(sub.controller9020 - 1))
		}
	}
	return installed
}

func (m *Machine) ccrMask9020(position uint32) uint32 {
	if m.cfg.Model9020E {
		// A27-9020-01 fig. 8-2. Word 1 has separate SE and DE fields.
		const stateAndScan = stateMask9020 | 0x38000000
		const ces, ses, des = 0x00000e00, 0x00f80000, 0x0007c000
		switch {
		case position < 8: // RCU and TCU.
			return stateAndScan | ioceMask9020E
		case position < 13:
			return stateAndScan | ces | ioceMask9020E
		case position < 18:
			return stateAndScan | 0x01000000 | ces
		case position < 24:
			return stateAndScan | inhibitLOS9020 | ses | des | ces | ioceMask9020E
		default: // IOCEs cannot access DEs.
			return stateAndScan | inhibitLOS9020 | ses | ces
		}
	}
	if !m.cfg.Model9020A && (position >= firstTCU9020 && position <= lastTCU9020 ||
		position >= firstSCU9020 && position <= lastSCU9020) {
		return stateMask9020 | scanMask9020 | ioceMask9020
	}
	slots := m.storageSlots9020()
	if position < 8+uint32(slots) { // Storage elements accept CE and IOCE communication.
		return stateMask9020 | scanMask9020 | ceMask9020 | ioceMask9020
	}
	connectedStorage := uint32(seMask9020)
	if m.cfg.Model9020A {
		connectedStorage = 0x00fff000
	}
	if position < 24 { // The CE may communicate with the other CEs.
		return stateMask9020 | scanMask9020 | inhibitLOS9020 | connectedStorage | ceMask9020 | ioceMask9020
	}
	return stateMask9020 | scanMask9020 | inhibitLOS9020 | connectedStorage | ceMask9020
}

// AttachTape9020 connects a tape device to the selected TCU. Its device
// number specifies the physical channel path. Between Run calls, other
// tape drives can be attached to the same TCU on their own paths.
func (s *ChannelSubsystem) AttachTape9020(devno uint16, tape *Tape2401, unit int) (uint16, error) {
	if unit < 1 || unit > lastTCU9020-firstTCU9020+1 || s.m.cfg.Model9020E && (unit > 2 || devno>>10 >= 2) {
		return 0, fmt.Errorf("9020 tape control: invalid TCU %d or device %04X", unit, devno)
	}
	return s.attachControl9020(devno, tape, firstTCU9020+unit-1)
}

// AttachDASD9020 connects a 2314 device to the selected 9020D SCU.
func (s *ChannelSubsystem) AttachDASD9020(devno uint16, disk *DASD3390, unit int) (uint16, error) {
	if s.m.cfg.Model9020E || disk.devType != 0x2314 || unit < 1 || unit > lastSCU9020-firstSCU9020+1 {
		return 0, fmt.Errorf("9020 storage control: SCU %d requires a 2314 and a controller number from 1 to 3", unit)
	}
	return s.attachControl9020(devno, disk, firstSCU9020+unit-1)
}

func (s *ChannelSubsystem) attachControl9020(devno uint16, device Device, position int) (uint16, error) {
	if !s.m.Model9020 || s.m.cfg.Model9020A || s.m.cfg.IOCE || devno>>10 >= 3 {
		return 0, fmt.Errorf("9020 control: device %04X requires a 9020D/E channel path", devno)
	}
	number, err := s.Attach(devno, device)
	if err == nil {
		s.bydev[devno].controller9020 = uint8(position + 1)
	}
	return number, err
}

// The IOCE–TCU and IOCE–SCU fields are in the control unit's CCR.
// See A27-9020-01 figure 8-2 and FAA DD8A0900 routines 9 and A.
func (s *ChannelSubsystem) controlConfigured9020(x *Subchannel) bool {
	if p, ok := x.dev.(*rcu9020Port); ok {
		return p.rcu.activeBase() == p.base
	}
	return x.controller9020 == 0 ||
		s.m.configurationListens9020(uint32(x.controller9020-1), 29+uint32(x.devno>>10))
}

func (m *Machine) ccr9020(position uint32) uint32 {
	if reg := m.configuration9020[position]; reg.Set {
		return reg.Word
	}
	if m.cfg.Model9020E && position < 2 {
		if rcu := m.CSS.rcus9020[position]; rcu != nil {
			return (scanMask9020 | configurationBit9020(29+uint32(rcu.primary>>10))) & m.ccrMask9020(position)
		}
	}
	// The emulator starts with the installed elements connected and
	// available for configuration. Only explicit changes restrict a link.
	return (stateMask9020 | scanMask9020 | m.installedElements9020()) & m.ccrMask9020(position)
}

func (c *CPU) setConfiguration9020(r1, r2 int) {
	c.privileged()
	if c.Addr >= 4 || r1&1 != 0 {
		c.program(pgmSpecification)
	}
	installed := c.M.installedElements9020()
	source := uint32(20 + c.Addr)
	issuer := c.M.ccr9020(source)
	requester := configurationBit9020(2 + uint32(c.Addr))
	mask, missed := c.GR[r1], c.GR[r2]
	rcuChanged := false
	state := issuer & stateMask9020
	installedScan := (installed & ceMask9020) << 18
	if state != 0 && state != stateMask9020 || issuer&requester == 0 || mask&installedScan == 0 ||
		missed&ioceMask9020 != 0 && bits.OnesCount32(mask&ceMask9020) > 1 {
		c.program(pgmSpecification)
	}
	for targets := missed & installed; targets != 0; {
		position := uint32(bits.LeadingZeros32(targets))
		bit := configurationBit9020(position)
		targets &^= bit
		ccr := c.M.ccr9020(position)
		rcu := c.M.cfg.Model9020E && position < 2
		if ccr&requester != 0 || rcu && ccr&stateMask9020 != 0 && ccr&scanMask9020 == 0 {
			c.M.configuration9020[position] = configRegister9020{Word: mask & c.M.ccrMask9020(position), Set: true}
			const firstDisplay = 8 + max9020EStorageElements
			if de := position - firstDisplay; c.M.cfg.Model9020E && de < uint32(c.M.cfg.DisplayElements9020E) &&
				!c.M.configureDisplay9020E(int(de), uint16(c.GR[r1+1]>>16)) {
				continue
			}
			// A multiple-IOCE assignment reaches the RCU CCR even though
			// the unit withholds its SCON response (Design Data fig. 10-8).
			if !rcu || bits.OnesCount32(mask&ioceMask9020E) <= 1 {
				missed &^= bit
			}
			rcuChanged = rcuChanged || rcu
		}
	}
	if rcuChanged {
		c.M.CSS.presentRCUAttention9020()
	}
	for _, cpu := range c.M.CPUs {
		cpu.purgeTLB()
		cpu.ipageValid = false
		cpu.pswChanged = true
	}
	c.GR[r1], c.PSW.CC = missed, 0
	if missed != 0 {
		c.PSW.CC = 2
	}
}

func (m *Machine) configurationListens9020(receiver, sender uint32) bool {
	reg := m.configuration9020[receiver]
	return !reg.Set || reg.Word&configurationBit9020(sender) != 0
}

func (m *Machine) configurationLink9020(first, second uint32) bool {
	return m.configurationListens9020(first, second) && m.configurationListens9020(second, first)
}

func (c *CPU) storageConfigured9020(address uint32) bool {
	se := address / c.M.storageElementSize9020()
	return !c.M.Model9020 || c.M.cfg.IOCE || c.Addr >= 4 || se >= uint32(c.M.storageSlots9020()) ||
		c.M.configurationLink9020(20+uint32(c.Addr), 8+se)
}

func (c *CPU) ioceConfigured9020(ioce uint16) bool {
	return !c.M.Model9020 || c.M.cfg.IOCE || c.Addr >= 4 || ioce >= 3 ||
		c.M.configurationLink9020(20+uint32(c.Addr), 29+uint32(ioce))
}

func (c *CPU) logoutStopInhibited9020() bool {
	return c.Addr < 4 && c.M.configuration9020[20+c.Addr].Word&inhibitLOS9020 != 0
}

func (s *ChannelSubsystem) ioceStorageConfigured9020(devno uint16, address uint32) bool {
	if s.m.isDisplayAddress9020(address) && !s.machAddress(address) {
		return false
	}
	ioce, se := devno>>10, address/s.m.storageElementSize9020()
	return !s.m.Model9020 || s.m.cfg.IOCE || ioce >= 3 || se >= uint32(s.m.storageSlots9020()) || s.machAddress(address) ||
		s.m.configurationLink9020(29+uint32(ioce), 8+se)
}
