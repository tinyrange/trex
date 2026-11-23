package s390

import "fmt"

// A 2821 can be reserved independently of its attached units. A side is
// numbered 1 or 2, with zero denoting the neutral state (GA24-3312).
type switch2821 struct {
	units []*UnitRecord
	state switch2821State
}

type switch2821State struct {
	Owner byte
	Wait  [2]bool
}

type unit2821State struct {
	Owner byte
	Check byte
	Wait  [2]bool
}

type unit2821Port struct {
	control *switch2821
	paths   [2]*Subchannel
	state   unit2821State
}

// Attach2821Switch connects existing 2821 devices to a second interface.
// The first pair identifies printer 1, which presents control-unit end.
func (s *ChannelSubsystem) Attach2821Switch(pairs [][2]uint16) error {
	if !s.m.S370 || len(pairs) == 0 {
		return fmt.Errorf("2821 switch requires System/360 or System/370 channels and a printer pair")
	}
	control := &switch2821{}
	seen := make(map[uint16]bool)
	unitTypes := [5]uint16{0x1403, 0x2540, 0x2541, 0x1403, 0x1403}
	for i, pair := range pairs {
		first, second := pair[0], pair[1]
		x := s.bydev[first]
		unit := first & 7
		if x == nil || s.bydev[second] != nil || seen[first] || seen[second] ||
			first&^7 != pairs[0][0]&^7 || second&^7 != pairs[0][1]&^7 ||
			first>>8 == second>>8 || second&7 != unit || unit >= uint16(len(unitTypes)) || i == 0 && unit != 0 {
			return fmt.Errorf("invalid 2821 device pair %04X/%04X", first, second)
		}
		u, ok := x.dev.(*UnitRecord)
		if !ok || u.port != nil || u.Type != unitTypes[unit] {
			return fmt.Errorf("invalid 2821 unit at %04X", first)
		}
		seen[first], seen[second] = true, true
		control.units = append(control.units, u)
	}
	for i, pair := range pairs {
		u := control.units[i]
		if _, err := s.Attach(pair[1], u); err != nil {
			return err
		}
		u.port = &unit2821Port{control: control, paths: [2]*Subchannel{s.bydev[pair[0]], s.bydev[pair[1]]}}
	}
	return nil
}

func (p *unit2821Port) side(x *Subchannel) byte {
	if x == p.paths[0] {
		return 1
	}
	return 2
}

func (c *switch2821) holdsControl(side byte) bool {
	if c.state.Owner == side {
		return true
	}
	for _, u := range c.units {
		p := u.port
		x := p.paths[side-1]
		// A channel can already have accepted CE while its interruption
		// is still pending for the CPU. Only device-held CE ties up the CU.
		if p.state.Check == side || x.finishAt != 0 || x.blocked && x.resumeAt == 0 ||
			x.devPending && x.devStatus&usCE != 0 {
			return true
		}
	}
	return false
}

func (p *unit2821Port) holdsUnit(side byte) bool {
	x := p.paths[side-1]
	return p.state.Owner == side || x.working() || x.deAt != 0 || x.devPending && x.devStatus&usDE != 0
}

func (p *unit2821Port) selectStatus(s *ChannelSubsystem, x *Subchannel) byte {
	side := p.side(x)
	other := 3 - side
	if p.control.holdsControl(other) {
		p.control.state.Wait[side-1] = true
		return usSM | usBusy
	}
	printer := p.control.units[0].port.paths[side-1]
	if printer.pending && printer.devPending && printer.devStatus == usCUE {
		s.accept370(printer)
		return usSM | usBusy | usCUE
	}
	if p.holdsUnit(other) {
		p.state.Wait[side-1] = true
		return usBusy
	}
	return 0
}

func (c *switch2821) notify() {
	for i := range 2 {
		other := byte(2 - i)
		if c.holdsControl(other) {
			continue
		}
		printer := c.units[0].port.paths[i]
		if c.state.Wait[i] {
			if !printer.pending && !printer.working() {
				c.state.Wait[i] = false
				printer.presentDeviceStatus(usCUE)
			}
			continue
		}
		var waiting *unit2821Port
		priority := 5
		for _, u := range c.units {
			p := u.port
			x := p.paths[i]
			if x.devPending && (x.devStatus == usCUE || x.devStatus == usDE) {
				// The 2821 presents one unsolicited status at a time.
				waiting = nil
				break
			}
			if p.state.Wait[i] && !p.holdsUnit(other) && !x.pending && !x.working() {
				// A 2540 reader has priority over its punch, followed
				// by the printers in control-unit order.
				rank := [5]int{2, 0, 1, 3, 4}[x.devno&7]
				if rank < priority {
					waiting, priority = p, rank
				}
			}
		}
		if waiting != nil {
			waiting.state.Wait[i] = false
			waiting.paths[i].presentDeviceStatus(usDE)
		}
	}
}

func (u *UnitRecord) exec2821(x *Subchannel, cmd byte, data []byte, chained bool) ([]byte, int, byte) {
	p := u.port
	side := p.side(x)
	if cmd&0x1f == 0x14 {
		if x.ccws != 0 {
			p.state.Check = side
			return u.reject()
		}
		switch cmd {
		case 0x14, 0x34, 0xd4:
			p.control.state.Owner = 0
		case 0x54, 0x74, 0xf4:
			p.control.state.Owner = side
		}
		switch cmd {
		case 0x14, 0x54, 0x94:
			p.state.Owner = 0
		case 0x34, 0x74, 0xb4:
			p.state.Owner = side
		}
		cmd = 0x04
	}
	out, used, status := u.Exec(cmd, data, chained)
	switch {
	case status&usUnitCheck != 0:
		p.state.Check = side
	case cmd != 0x03:
		p.state.Check = 0
	}
	return out, used, status
}
