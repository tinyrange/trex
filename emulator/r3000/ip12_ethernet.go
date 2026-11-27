package r3000

// The SEEQ 8003 and its HPC1 channel are initialized even without a network
// link. A disconnected machine never receives frames.
type ip12Ethernet struct {
	dma     [22]uint32
	station [6]byte
	tx      byte
}

func (e *ip12Ethernet) channel(offset, value uint32, write bool) (uint32, bool) {
	reg := &e.dma[offset/4]
	switch offset {
	case 0:
		return 0, !write // No Ethernet transmit count pending.
	case 0x0c, 0x10, 0x14, 0x20, 0x24, 0x28, 0x2c, 0x34, 0x38, 0x48, 0x4c, 0x50, 0x54:
		if write {
			*reg = value
		}
	case 0x3c:
		if write {
			if value&1 != 0 {
				*e = ip12Ethernet{}
			}
			*reg = value & 0xf
		}
	default:
		return 0, false
	}
	return *reg, true
}

func (e *ip12Ethernet) seeq(index uint32, value byte, write bool) uint32 {
	switch index {
	case 6:
		return 0 // No receive status pending.
	case 7:
		if write {
			e.tx = value
		}
		return 0x80 // Transmitter idle.
	default:
		if e.tx&0x60 != 0 {
			return 0
		}
		if write {
			e.station[index] = value
		}
		return uint32(e.station[index])
	}
}
