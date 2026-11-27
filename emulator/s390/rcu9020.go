package s390

import (
	"fmt"
	"math/bits"
	"time"
)

// The 7265-03 RCU shares its shift register, sense and attention scanner
// across its channel addresses (IBM 9020D/E System Design Data, chapter 10).
type rcu9020 struct {
	css       *ChannelSubsystem
	unit      int
	primary   uint16
	alternate int
	count     uint16
	state     rcuState9020
}

type rcuState9020 struct {
	Communication, Attention, Reports uint32
	Wrap                              [4]uint16
	WrapValid                         bool
	DAU                               [2]byte
	Sense                             byte
	BusyEnd                           bool
}

type rcu9020Port struct {
	rcu    *rcu9020
	base   uint16
	offset uint16
}

// AttachRCU9020 attaches a 7265-03 to one or two multiplexor paths.
// A base represents the address just before the first DG interface.
// Use alternate -1 for a single path. The console size is 60 or 90.
func (s *ChannelSubsystem) AttachRCU9020(unit int, primary uint16, alternate, consoles int) error {
	if !s.m.cfg.Model9020E || s.m.cfg.IOCE || unit < 1 || unit > 2 || s.rcus9020[unit-1] != nil {
		return fmt.Errorf("9020 RCU: unit %d requires a free RCU position on a 9020E CE", unit)
	}
	count := uint16(19)
	switch consoles {
	case 60:
	case 90:
		count = 27
	default:
		return fmt.Errorf("9020 RCU: console size must be 60 or 90")
	}
	bases := []uint16{primary}
	if alternate != -1 {
		if alternate < 0 || alternate >= 0x800 || int(primary>>10) == alternate>>10 {
			return fmt.Errorf("9020 RCU: paths must belong to different IOCEs")
		}
		bases = append(bases, uint16(alternate))
	}
	for _, base := range bases {
		if base>>10 >= 2 || base&0x300 != 0 || base&0x3f != 0x20 {
			return fmt.Errorf("9020 RCU: invalid multiplexor base %04X", base)
		}
		for i := uint16(1); i <= count; i++ {
			if err := s.checkAttachment(base + i); err != nil {
				return err
			}
		}
	}
	r := &rcu9020{css: s, unit: unit, primary: primary, alternate: alternate, count: count}
	for _, base := range bases {
		for i := uint16(1); i <= count; i++ {
			if _, err := s.attachControl9020(base+i, &rcu9020Port{rcu: r, base: base, offset: i}, unit-1); err != nil {
				return err
			}
		}
	}
	s.rcus9020[unit-1] = r
	return nil
}

func (r *rcu9020) ccr() uint32 { return r.css.m.ccr9020(uint32(r.unit - 1)) }

// In states one and two an RCU's communication bits apply to both
// controllers, provided the other is in state three (Design Data 10-4).
func (r *rcu9020) outboardConfigured(offset uint16) bool {
	state := r.ccr() & stateMask9020
	peer := r.css.rcus9020[2-r.unit]
	var peerState uint32
	if peer != nil {
		peerState = peer.ccr() & stateMask9020
	}
	bit := uint32(1) << offset
	switch {
	case state == 0:
		return false
	case state == stateMask9020 && peerState != 0 && peerState != stateMask9020:
		return peer.state.Communication&bit == 0
	default:
		return (state == stateMask9020 || peerState == stateMask9020) && r.state.Communication&bit != 0
	}
}

func (r *rcu9020) activeBase() uint16 {
	mask := r.ccr() & ioceMask9020E
	if mask != 0 {
		ioce := uint16(bits.LeadingZeros32(mask) - 29)
		if r.primary>>10 == ioce {
			return r.primary
		}
		if r.alternate >= 0 && uint16(r.alternate)>>10 == ioce {
			return uint16(r.alternate)
		}
	}
	return 0xffff
}

func (p *rcu9020Port) bit() uint32 { return 1 << p.offset }

func (p *rcu9020Port) isDG() bool {
	return p.offset <= 12 || p.offset >= 20 && p.offset <= 24
}

func (p *rcu9020Port) isDAU() bool { return p.offset == 18 || p.offset == 19 }

func (p *rcu9020Port) configSize() int {
	if p.isDAU() {
		return 1
	}
	if p.offset == 16 || p.offset == 17 || p.offset == 27 {
		return 4
	}
	return 2
}

func (p *rcu9020Port) SenseID() []byte { return nil }
func (p *rcu9020Port) Reset()          { p.rcu.state = rcuState9020{} }
func (p *rcu9020Port) StartChain()     { p.EndChain() }
func (p *rcu9020Port) EndChain() {
	p.rcu.state.Wrap = [4]uint16{}
	p.rcu.state.WrapValid = false
}

func (p *rcu9020Port) Exec(cmd byte, data []byte, _ bool) ([]byte, int, byte) {
	const end = usCE | usDE
	r, bit := p.rcu, p.bit()
	state := r.ccr() & stateMask9020
	switch cmd {
	case 0x03: // Control NOP.
		return nil, 0, end
	case 0x04: // Sense does not clear the previous operation's checks.
		var ccrSense byte
		if bits.OnesCount32(r.ccr()&ioceMask9020E) > 1 {
			ccrSense = 0x10 // CCR Program Check.
		}
		return []byte{r.state.Sense, ccrSense}, 0, end
	case 0x31, 0x22: // Write and Read Configuration.
	case 0x12, 0x07, 0x47, 0x57, 0x67, 0x77, 0x1f, 0x9f, 0x2f, 0xaf:
		if !p.isDAU() {
			break
		}
		fallthrough
	default:
		r.state.Sense = 0x80 // Command Reject.
		return nil, 0, usUnitCheck
	}

	r.state.Sense = 0
	switch cmd {
	case 0x1f:
		r.state.Attention &^= bit
		return nil, 0, end
	case 0x9f:
		r.state.Attention |= bit
		return nil, 0, end
	case 0x2f, 0xaf:
		if state != 0 && state != stateMask9020 {
			return nil, 0, usUnitExcept
		}
		r.state.Communication &^= bit
		if cmd == 0xaf {
			r.state.Communication |= bit
		}
		return nil, 0, end
	}

	if state != 0 {
		if !p.isDAU() && !r.outboardConfigured(p.offset) {
			return nil, 0, usUnitExcept
		}
		return p.outboardCommand(cmd, data)
	}
	if !p.isDAU() && r.state.Communication&bit == 0 {
		return nil, 0, usUnitExcept
	}
	switch cmd {
	case 0x31:
		return p.writeConfiguration(data)
	case 0x22:
		return p.readConfiguration(), 0, end
	case 0x12:
		if p.isDG() {
			return []byte{0, 0x10}, 0, end
		}
		if p.configSize() == 2 {
			return []byte{0, 1, 0, 0}, 0, end
		}
		return make([]byte, 4), 0, end
	case 0x67:
		r.state.Reports |= bit
	}
	return nil, 0, end
}

func (p *rcu9020Port) writeConfiguration(data []byte) ([]byte, int, byte) {
	const end = usCE | usDE
	r, n := p.rcu, p.configSize()
	if len(data) < n {
		r.state.Sense = 1 // Wrong Length Message.
		return nil, n, end | usUnitCheck
	}
	if p.isDAU() {
		return p.writeDAU(data[0])
	}
	for i, value := range data[:n] {
		r.state.Wrap[i] |= uint16(value) | uint16(oddParity9020(value))<<8
	}
	r.state.WrapValid = true
	for _, lane := range r.state.Wrap[:n] {
		if uint32(lane>>8) != oddParity9020(byte(lane)) {
			r.state.Sense = 8 // Data Check.
			return nil, n, end | usUnitCheck
		}
	}
	return nil, n, end
}

func (p *rcu9020Port) readConfiguration() []byte {
	r := p.rcu
	if p.isDAU() {
		return []byte{r.state.DAU[p.offset-18]}
	}
	out := make([]byte, p.configSize())
	if r.state.WrapValid {
		for i := range out {
			out[i] = byte(r.state.Wrap[i])
		}
		if p.isDG() {
			out[1] = out[1]&^0x20 | 0x10 // FAA D9051200, DGDATA.
		}
	}
	return out
}

func (p *rcu9020Port) writeDAU(value byte) ([]byte, int, byte) {
	const end = usCE | usDE
	if value&0xf1 == 0xf1 {
		p.rcu.state.Sense = 8
		return nil, 1, end | usUnitCheck
	}
	result := value & 0xc0
	if value&1 != 0 {
		// Reset folds the two state bits into the two interface bits
		// on diagnostic readback (Design Data §10, Diagnostic Facilities).
		result = (value & 0x30) << 2
	}
	p.rcu.state.DAU[p.offset-18] = result
	return nil, 1, end
}

func (p *rcu9020Port) CommandTiming(cmd byte, n int) (time.Duration, time.Duration) {
	switch cmd {
	case 0x04, 0x12, 0x22, 0x31:
		// The CI clocks serial data at 1 MHz in addition to the channel
		// handshakes. Exact byte-service timing is outside the CI transfer.
		return time.Duration(max(n, 1)) * 8 * time.Microsecond, 0
	default:
		return 0, 0
	}
}

func (p *rcu9020Port) TestIOStatus() byte {
	r := p.rcu
	if r.working(p.base + p.offset) {
		r.state.BusyEnd = true
		return usSM | usBusy
	}
	return 0
}

func (r *rcu9020) working(except uint16) bool {
	for _, base := range [...]int{int(r.primary), r.alternate} {
		if base < 0 {
			continue
		}
		for i := uint16(1); i <= r.count; i++ {
			addr := uint16(base) + i
			if addr != except && r.css.bydev[addr].working() {
				return true
			}
		}
	}
	return false
}

func (r *rcu9020) presentAttention() {
	ready := r.state.Reports & r.state.Attention
	diagnostic := r.ccr()&stateMask9020 == 0
	if !diagnostic {
		ready = 0
		for offset := uint16(1); offset <= r.count; offset++ {
			if bit := uint32(1) << offset; r.state.Attention&bit != 0 &&
				r.css.rcuEndpoints9020[offset].Report && r.outboardConfigured(offset) {
				ready |= bit
			}
		}
	}
	base := r.activeBase()
	if ready == 0 || base == 0xffff || r.working(0xffff) {
		return
	}
	for i := uint16(1); i <= r.count; i++ {
		x := r.css.bydev[base+i]
		if x.pending {
			return // The scanner presents one attention at a time.
		}
	}
	offset := uint16(bits.TrailingZeros32(ready))
	if r.css.Unsolicited(base+offset, usAttention) {
		if diagnostic {
			r.state.Reports &^= 1 << offset
		} else {
			r.css.rcuEndpoints9020[offset].Report = false
		}
	}
}

func (s *ChannelSubsystem) presentRCUAttention9020() {
	for _, rcu := range s.rcus9020 {
		if rcu != nil {
			rcu.presentAttention()
		}
	}
}

func (p *rcu9020Port) attentionPending() bool {
	r := p.rcu
	if r.state.Attention&p.bit() == 0 {
		return false
	}
	if r.ccr()&stateMask9020 == 0 {
		return r.state.Reports&p.bit() != 0
	}
	return r.outboardConfigured(p.offset) && r.css.rcuEndpoints9020[p.offset].Report
}

type rcuSnapshot9020 struct {
	Primary         uint16
	Unit, Alternate int
	Count           uint16
	State           rcuState9020
}

func (p *rcu9020Port) snapshotKind() string { return "7265-03-rcu" }
func (p *rcu9020Port) snapshot() ([]byte, error) {
	r := p.rcu
	return encodeGob(rcuSnapshot9020{r.primary, r.unit, r.alternate, r.count, r.state})
}

func (p *rcu9020Port) restore(data []byte, _ bool) error {
	var snap rcuSnapshot9020
	if err := decodeGob(data, &snap); err != nil {
		return err
	}
	r := p.rcu
	if r.primary != snap.Primary || r.unit != snap.Unit || r.alternate != snap.Alternate || r.count != snap.Count {
		return fmt.Errorf("9020 RCU: interface configuration differs from checkpoint")
	}
	r.state = snap.State
	return nil
}
