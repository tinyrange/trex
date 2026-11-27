package r3000

import "github.com/tinyrange/trex/channel"

// The Z8530's two channels share the interrupt controller but have independent
// register selects and data paths.
type ip12SCC struct {
	ports [2]ip12SCCPort
}

type ip12SCCPort struct {
	stream   *channel.Memory
	selected byte
	wr       [16]byte
	rx       byte
	rxReady  bool
	txIRQ    bool
}

func (p *ip12SCCPort) poll() {
	if p.stream != nil && !p.rxReady && p.wr[3]&1 != 0 {
		var b [1]byte
		n, _ := p.stream.ReadAvailable(b[:])
		if n != 0 {
			p.rxReady, p.rx = true, b[0]
		}
	}
}

func (s *ip12SCC) pending() byte {
	var bits byte
	for i := range s.ports {
		p := &s.ports[i]
		p.poll()
		if p.rxReady && p.wr[1]&0x18 != 0 {
			bits |= 4 << (3 * (1 - i))
		}
		if p.txIRQ && p.wr[1]&2 != 0 {
			bits |= 2 << (3 * (1 - i))
		}
	}
	return bits
}

func (s *ip12SCC) irq() bool {
	return s.ports[0].wr[9]&8 != 0 && s.pending() != 0
}

func (s *ip12SCC) access(index uint32, value byte, write bool) uint32 {
	// HPC exposes B control, B data, A control, A data.
	port := int((index >> 1) ^ 1)
	p := &s.ports[port]
	if index&1 != 0 {
		if write {
			if p.stream != nil && p.wr[5]&8 != 0 {
				_, _ = p.stream.WriteAvailable([]byte{value})
			}
			p.txIRQ = true
			return 0
		}
		p.poll()
		if p.rxReady {
			p.rxReady = false
			return uint32(p.rx)
		}
		return 0
	}
	selected := p.selected
	p.selected = 0
	if write {
		switch selected {
		case 0:
			p.selected = value & 7
			switch value >> 3 & 7 {
			case 1:
				p.selected |= 8
			case 5:
				p.txIRQ = false
			}
		case 9:
			for i := range s.ports {
				if value&(0x80>>i) != 0 {
					stream := s.ports[i].stream
					s.ports[i] = ip12SCCPort{stream: stream}
				}
			}
			s.ports[0].wr[9] = value & 0x3f
		default:
			if selected == 1 && p.wr[1]&2 == 0 && value&2 != 0 {
				p.txIRQ = true
			}
			p.wr[selected] = value
		}
		return 0
	}
	switch selected {
	case 0:
		p.poll()
		return 0x2c | truth(p.rxReady) // CTS, DCD, TX empty.
	case 1:
		return 1 // All sent.
	case 2:
		return uint32(s.ports[0].wr[2])
	case 3:
		if port == 0 {
			return uint32(s.pending())
		}
	case 12, 13:
		return uint32(p.wr[selected])
	}
	return 0
}
