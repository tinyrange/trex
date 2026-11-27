package s390

import "math/bits"

// The configuration interface remains available when the endpoint is
// stopped or its normal interfaces are disabled (9020E FETOM pp. 3-36–37).
// Its state belongs to the endpoint shared by both RCUs.
type rcuEndpoint9020 struct {
	Configuration  [4]byte
	Status         [4]byte
	Stopped        bool
	InterfacesOff  bool
	Report         bool
	RCONConfigured bool
	RKM            rkm9020E
}

func (e *rcuEndpoint9020) raiseStatus(index int, mask byte) {
	if e.Status[index]&mask == 0 {
		e.Status[index] |= mask
		e.Report = true
	}
}

// DAU ports 1–5 correspond to the RKM numbers. RKM 4 and 5 are available
// on the 90-console profile (Design Data, fig. 10-7).
var rkmOffsets9020E = [...]uint16{13, 14, 15, 25, 26}

func (s *ChannelSubsystem) radarKeyboard9020E(number uint16) *rcuEndpoint9020 {
	if number == 0 || int(number) > len(rkmOffsets9020E) {
		return nil
	}
	offset := rkmOffsets9020E[number-1]
	for _, rcu := range s.rcus9020 {
		if rcu != nil && offset <= rcu.count {
			return &s.rcuEndpoints9020[offset]
		}
	}
	return nil
}

func (s *ChannelSubsystem) nextRKM9020E() uint64 {
	var next uint64
	for _, offset := range rkmOffsets9020E {
		e := &s.rcuEndpoints9020[offset]
		if e.Stopped {
			continue
		}
		deadlines := [4]uint64{e.RKM.Operator.deadline()}
		if !e.InterfacesOff {
			deadlines[1], deadlines[2], deadlines[3] = e.RKM.FetchAt, e.RKM.PollAt, e.RKM.ReplyBy
		}
		for _, at := range deadlines {
			if at != 0 && (next == 0 || at < next) {
				next = at
			}
		}
	}
	return next
}

func (s *ChannelSubsystem) tickRKM9020E(now uint64) {
	for i, offset := range rkmOffsets9020E {
		e := &s.rcuEndpoints9020[offset]
		number := uint16(i + 1)
		if e.Stopped {
			continue
		}
		if at := e.RKM.Operator.deadline(); at != 0 && now >= at && e.advanceRKMOperator(now) {
			s.presentRCUAttention9020()
		}
		if e.InterfacesOff {
			continue
		}
		rkm := &e.RKM
		if at := rkm.FetchAt; at != 0 && now >= at {
			s.finishRKMFetch(number, e)
			s.notifyDAU9020E()
		}
		if at := rkm.ReplyBy; at != 0 && now >= at {
			rkm.ReplyBy, rkm.PollAt, rkm.Polling = 0, 0, false
			e.raiseStatus(0, 0x08)
			s.presentRCUAttention9020()
		}
		if at := rkm.PollAt; at != 0 && now >= at {
			s.pollRKM(number, e, at)
			s.notifyDAU9020E()
			s.presentRCUAttention9020()
		}
	}
}

func (p *rcu9020Port) outboardCommand(cmd byte, data []byte) ([]byte, int, byte) {
	const end = usCE | usDE
	r := p.rcu
	e := &r.css.rcuEndpoints9020[p.offset]
	size := p.configSize()
	dg := p.isDG()
	now := r.css.m.tod
	if !dg && size == 2 && e.advanceRKMOperator(now) {
		r.css.presentRCUAttention9020()
	}
	var dau *dau2701
	if p.isDAU() {
		dau = r.css.dauUnits9020[p.offset-18]
	}
	switch cmd {
	case 0x31: // Write Configuration.
		if len(data) < size {
			r.state.Sense = 1
			return nil, size, end | usUnitCheck
		}
		if p.isDAU() && data[0]&0xc0 == 0xc0 {
			r.state.Sense = 8 // The DAU rejected both channel interfaces.
			return nil, size, end | usUnitCheck
		}
		if dau != nil {
			dau.setConfiguration(data[0])
			r.css.notifyDAU9020E()
			return nil, size, end
		}
		copy(e.Configuration[:], data[:size])
		switch {
		case dg:
			e.Configuration[1] &= 0xc0 // The RCU supplies the storage word size on readback.
		case p.isDAU():
			e.Configuration[0] &= 0xc0 // The other inputs are orders, not readback bits.
		case size == 2:
			e.Configuration[0] &= 0xfc
			e.Configuration[1] = 0
		case size == 4:
			e.RCONConfigured = true
			r.css.schedulePendingRKMInput()
		}
		if dg {
			r.css.m.scheduleRadarDisplays9020E()
		} else if size == 2 {
			r.css.notifyDAU9020E()
		}
		return nil, size, end
	case 0x22: // Read Configuration.
		if dau != nil {
			return []byte{dau.configuration & 0xc0}, 0, end
		}
		out := e.Configuration
		if dg {
			out[1] |= 0x10
		}
		return out[:size], 0, end
	case 0x12: // Read Status. RKM/R console status is four zero bytes.
		out := e.Status
		if dg {
			return out[:2], 0, end
		}
		return out[:], 0, end
	case 0x07: // Reset.
		e.Status, e.Report = [4]byte{}, false
		e.Stopped, e.InterfacesOff = false, false
		e.RKM = rkm9020E{Memory: e.RKM.Memory, Consoles: e.RKM.Consoles, Input: e.RKM.Input}
	case 0x47: // Stop.
		if op := &e.RKM.Operator; op.Order != 0 && op.PausedAt == 0 {
			op.PausedAt = now
		}
		if !e.Stopped {
			e.RKM.PausedAt = now
		}
		e.Stopped = true
	case 0x57: // Resume.
		if op := &e.RKM.Operator; op.PausedAt != 0 {
			op.Next += now - op.PausedAt
			op.PausedAt = 0
		}
		if e.Stopped {
			rkm := &e.RKM
			for _, at := range [...]*uint64{&rkm.FetchAt, &rkm.PollAt, &rkm.ReplyBy} {
				if *at != 0 {
					*at += now - rkm.PausedAt
				}
			}
			rkm.PausedAt = 0
		}
		e.Stopped = false
		if !dg && size == 2 {
			r.css.schedulePendingRKMInput()
			r.css.notifyDAU9020E()
		}
	case 0x77: // Disable Interfaces.
		e.InterfacesOff = true
	case 0x67: // Test.
		if dg {
			e.raiseStatus(1, 0x10)
		} else if size == 2 {
			e.raiseStatus(1, 0x01)
		}
	}
	if dg {
		r.css.m.scheduleRadarDisplays9020E()
	}
	return nil, 0, end
}

// Physical DE tails in the standard 60- and 90-PVD installations.
// Numbers are DGs, with 1 and 2 representing the two spares. Zero means
// unconnected (IBM 9020D/E System Design Data, tables 4-6 and 4-7).
var displayTails60 = [4][8]uint16{
	{3, 4, 5, 6, 7, 0, 1, 2},
	{5, 6, 7, 8, 9, 0, 0, 0},
	{8, 9, 10, 11, 12, 0, 1, 2},
	{10, 11, 12, 3, 4, 0, 0, 0},
}

var displayTails90 = [5][8]uint16{
	{3, 4, 5, 6, 7, 8, 1, 2},
	{6, 7, 8, 9, 10, 11, 0, 0},
	{9, 10, 11, 12, 13, 14, 1, 2},
	{12, 13, 14, 15, 16, 17, 0, 0},
	{15, 16, 17, 3, 4, 5, 0, 0},
}

func (s *ChannelSubsystem) radarDisplay9020E(de, tail int) *rcuEndpoint9020 {
	var ports uint16
	for _, r := range s.rcus9020 {
		if r != nil {
			ports = max(ports, r.count)
		}
	}
	var dg uint16
	switch {
	case ports == 27:
		dg = displayTails90[de][tail]
	case ports == 19 && de < len(displayTails60):
		dg = displayTails60[de][tail]
	}
	if dg == 0 {
		return nil
	}
	if dg > 12 {
		dg += 7 // D9051200, expanded DG addresses 34–38.
	}
	return &s.rcuEndpoints9020[dg]
}

func (e *rcuEndpoint9020) displayRequests() byte {
	if e == nil || e.Stopped || e.InterfacesOff || e.Configuration[0]&0x80 == 0 {
		return 0
	}
	return (e.Configuration[0]&0x0f)<<2 | e.Configuration[1]>>6
}

func (e *rcuEndpoint9020) receiveDisplay(pair [2]uint64) bool {
	if bits.OnesCount64(pair[0])&1 == 0 || bits.OnesCount64(pair[1])&1 == 0 {
		e.raiseStatus(0, 0x20) // DE Data Parity Error, Design Data table 10-9.
		return e.Report
	}
	return false
}

func (m *Machine) scheduleRadarDisplays9020E() {
	for de := range m.cfg.DisplayElements9020E {
		m.scheduleDisplay9020E(de)
	}
}
