package s390

import (
	"bytes"
	"fmt"
	"time"
)

// dau2701 models the 9020 DAU in state zero with the F26329 multidevice
// attachment. The five RKM addresses share a diagnostic register and sense.
// In state zero their diagnostic commands work with the external RKMs
// disconnected (A27-2734-2, appendix K).
type dau2701 struct {
	css             *ChannelSubsystem
	base            uint16
	peer            uint16
	paired          bool
	owner           byte // 0 neutral, 1 primary, 2 secondary
	register, sense byte
	attention       byte
	cuEndWanted     bool
}

// dau2701Port is one of the five RKM addresses decoded by the DAU.
type dau2701Port struct {
	dau  *dau2701
	addr uint16
	side byte
}

func (s *ChannelSubsystem) Attach2701(base uint16) error {
	return s.attach2701(base, 0, false)
}

func (s *ChannelSubsystem) attach2701(base, peer uint16, paired bool) error {
	bases := []uint16{base}
	if paired {
		if base == peer || byte(base) != byte(peer) {
			return fmt.Errorf("2701 two-processor interfaces require different channels with the same unit address")
		}
		bases = append(bases, peer)
	}
	for _, cuu := range bases {
		if !s.m.Model9020 || cuu > 0xbf8 || cuu&7 != 0 {
			return fmt.Errorf("2701 requires a 9020 and a DAU base address divisible by eight")
		}
		for addr := cuu + 1; addr <= cuu+5; addr++ {
			if s.bydev[addr] != nil {
				return fmt.Errorf("2701 port %04X already attached", addr)
			}
		}
	}
	d := &dau2701{css: s, base: base, peer: peer, paired: paired}
	for i, cuu := range bases {
		for addr := cuu + 1; addr <= cuu+5; addr++ {
			if _, err := s.Attach(addr, &dau2701Port{dau: d, addr: addr, side: byte(i + 1)}); err != nil {
				return err
			}
		}
	}
	return nil
}

func (p *dau2701Port) selected() bool {
	return p.dau.owner == 0 || p.dau.owner == p.side
}

func (d *dau2701) baseFor(side byte) uint16 {
	if side == 2 {
		return d.peer
	}
	return d.base
}

func (p *dau2701Port) SenseID() []byte { return nil }

func (p *dau2701Port) Reset() {
	d := p.dau
	d.register, d.sense, d.attention = 0, 0, 0
	d.owner = 0
	d.cuEndWanted = false
}

func (p *dau2701Port) Exec(cmd byte, data []byte, chained bool) ([]byte, int, byte) {
	return p.exec(cmd, data, 1)
}

func (p *dau2701Port) exec(cmd byte, data []byte, count int) ([]byte, int, byte) {
	d := p.dau
	if d.paired {
		// Address selection of a neutral switch seizes the interface.
		// Release passes the command but leaves the switch neutral.
		if cmd == 0xd4 {
			d.owner = 0
		} else {
			d.owner = p.side
		}
	}
	switch cmd {
	case 0x03, 0xd4, 0xf4:
		return nil, 0, usCE | usDE
	case 0x04:
		return []byte{d.sense}, 0, usCE | usDE
	case 0x09, 0x29:
		d.sense = 0
		if len(data) > 0 {
			d.register = data[len(data)-1]
		}
		if cmd == 0x29 {
			d.attention = 0x1f &^ (1 << (p.addr - d.baseFor(p.side) - 1))
			return nil, len(data), usCE | usDE | usAttention | usSM | usUnitExcept
		}
		return nil, len(data), usCE | usDE
	case 0x0a:
		return bytes.Repeat([]byte{d.register}, count), 0, usCE | usDE
	}
	if formatted, ok := formatRKMCommand(cmd); ok {
		d.register = formatted
		d.sense = 0x01 // no response from the disconnected RKM
		return nil, 0, usCE | usDE | usUnitCheck
	}
	d.sense = 0x80
	return nil, 0, usUnitCheck
}

func (p *dau2701Port) CommandTiming(cmd byte, n int) (time.Duration, time.Duration) {
	switch cmd {
	case 0x03, 0xd4, 0xf4:
		return 0, 0
	case 0x09, 0x29, 0x0a, 0x04:
		return time.Duration(max(n, 1)) * 4 * time.Microsecond, 0
	default:
		return 2 * time.Microsecond, 0
	}
}

// formatRKMCommand maps channel commands to the order byte on the
// RKM interface (A27-2734-2, table K-II).
func formatRKMCommand(cmd byte) (byte, bool) {
	switch cmd {
	case 0x47:
		return 0x08, true // Disconnect
	case 0xc1, 0xe1:
		return 0x98 | (cmd&0x20)>>3, true // Write RKM
	case 0x81, 0xa1:
		return 0x90 | (cmd&0x20)>>3, true // Clear RKM Memory
	case 0x91, 0xb1:
		return 0x92 | (cmd&0x20)>>3, true // Blink Display
	case 0x21:
		return 0x84, true // Fetch Display Constants
	case 0x01:
		return 0x80, true // Load Queue Address
	case 0x61:
		return 0x8c, true // Move Data
	case 0x41:
		return 0x88, true // Special Move
	case 0xc2, 0xe2:
		return 0xd8 | (cmd&0x20)>>3, true // Read RKM
	case 0x02, 0x22:
		return 0xc0, true // Read Queue Address
	case 0x05, 0x25:
		return 0xa0 | (cmd&0x20)>>3, true // Load I/O Address
	case 0x85, 0xa5:
		return 0xb0 | (cmd&0x20)>>3, true // Keyboard Write
	case 0x06, 0x0e, 0x16:
		return (cmd - 0x06) >> 3, true // Read RKM status/error
	}
	if cmd&0x47 == 0x45 {
		return 0xa8 | (cmd&0x80)>>3 | (cmd>>3)&7, true // Bit Modify
	}
	return 0, false
}

func (p *dau2701Port) TestIOStatus() byte {
	d := p.dau
	base := d.baseFor(p.side)
	for addr := base + 1; addr <= base+5; addr++ {
		if addr != p.addr && d.css.bydev[addr].working() {
			d.cuEndWanted = true
			return usBusy | usSM
		}
	}
	return 0
}

func (d *dau2701) notify() {
	if d.attention == 0 {
		return
	}
	base := d.baseFor(d.owner)
	for i := uint16(0); i < 5; i++ {
		x := d.css.bydev[base+1+i]
		if x.working() || x.pending {
			return
		}
	}
	for i := uint16(0); i < 5; i++ {
		if bit := byte(1 << i); d.attention&bit != 0 {
			d.attention &^= bit
			d.css.bydev[base+1+i].presentDeviceStatus(usAttention | usSM | usUnitExcept)
			return
		}
	}
}

func (p *dau2701Port) snapshotKind() string { return "2701" }

func (p *dau2701Port) snapshot() ([]byte, error) {
	d := p.dau
	return encodeGob(dau2701Snap{Register: d.register, Sense: d.sense, Attention: d.attention, CUEndWanted: d.cuEndWanted,
		Paired: d.paired, Peer: d.peer, Owner: d.owner})
}

type dau2701Snap struct {
	Register, Sense, Attention byte
	CUEndWanted                bool
	Paired                     bool
	Peer                       uint16
	Owner                      byte
}

func (p *dau2701Port) restore(data []byte, _ bool) error {
	var snap dau2701Snap
	if err := decodeGob(data, &snap); err != nil {
		return err
	}
	if p.dau.paired != snap.Paired || p.dau.peer != snap.Peer {
		return fmt.Errorf("2701 interface configuration differs from checkpoint")
	}
	p.dau.register, p.dau.sense, p.dau.attention, p.dau.cuEndWanted = snap.Register, snap.Sense, snap.Attention, snap.CUEndWanted
	p.dau.owner = snap.Owner
	return nil
}
