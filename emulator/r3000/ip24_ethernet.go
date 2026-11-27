package r3000

// The onboard SEEQ 80C03 is present on a headless Indy, even with no
// Ethernet connection. The HPC3 exposes distinct receive and transmit
// descriptor pointers and a separate reset register.
type ip24Ethernet struct {
	receive, transmit [8]uint32
	station           [6]byte
	multicast         [8]byte
	receiveCommand    byte
	transmitCommand   byte
	control, config   byte
	reset, dmaConfig  uint32
	pioConfig         uint32
	rxCurrentDesc     uint32
	txCurrentDesc     uint32
	txPreviousDesc    uint32
}

func (e *ip24Ethernet) hpc(offset, data uint32, write bool) uint32 {
	var reg *uint32
	switch offset {
	case 0x4000:
		reg = &e.rxCurrentDesc
	case 0x6000:
		reg = &e.txCurrentDesc
	case 0x6004:
		reg = &e.txPreviousDesc
	}
	if reg != nil {
		if write {
			*reg = data
		}
		return *reg
	}
	channel := &e.receive
	if offset >= 0x2000 {
		channel = &e.transmit
		offset -= 0x2000
	}
	switch offset {
	case 0, 4:
		reg = &channel[offset/4]
	case 0x1000, 0x1004, 0x1008, 0x100c:
		reg = &channel[2+(offset-0x1000)/4]
	case 0x1014:
		if channel == &e.transmit {
			return 0
		}
		if write && data&1 != 0 {
			*e = ip24Ethernet{}
		}
		reg = &e.reset
	case 0x1018:
		reg = &e.dmaConfig
	case 0x101c:
		reg = &e.pioConfig
	default:
		return 0
	}
	if write {
		*reg = data
		if channel == &e.transmit && offset == 0x1004 {
			// A disconnected interface cannot hold a transfer active.
			*reg &^= 0x200
		}
	}
	return *reg
}

func (e *ip24Ethernet) seeq(index uint32, data byte, write bool) byte {
	if !write {
		if index == 5 {
			return 4 // No transmit carrier.
		}
		return 0
	}
	switch {
	case index == 6:
		e.receiveCommand = data
	case index == 7:
		e.transmitCommand = data
	case index < 6:
		switch e.transmitCommand & 0x60 {
		case 0:
			e.station[index] = data
		case 0x20:
			e.multicast[index] = data
		case 0x40:
			switch index {
			case 0, 1:
				e.multicast[index+6] = data
			case 3:
				e.control = data
			case 4:
				e.config = data
			}
		}
	}
	return 0
}
