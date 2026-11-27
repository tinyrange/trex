package r3000

import "encoding/binary"

const (
	ip12DMAAddress = 0x0fffffff
	ip12DMAEnd     = 0x80000000
	ip12DMAActive  = 0x80
	ip12DMAToRAM   = 0x10
)

type ip12DMA struct {
	count, buffer, next, control uint32
}

func (d *ip12DMA) descriptor(pic *ip12PIC) bool {
	data := pic.memory(d.next, 12)
	if d.next&3 != 0 || data == nil {
		return false
	}
	d.count = binary.BigEndian.Uint32(data) & 0x1fff
	d.buffer = binary.BigEndian.Uint32(data[4:]) & (ip12DMAAddress | ip12DMAEnd)
	d.next = binary.BigEndian.Uint32(data[8:]) & ip12DMAAddress
	return true
}

// transfer validates every RAM span before changing guest state. Progress is
// bounded by the WD33C93A transfer count, with empty descriptors terminating
// unless they carry the end-of-chain marker.
func (d *ip12DMA) transfer(pic *ip12PIC, data []byte, toRAM bool) bool {
	next := *d
	var spans [][]byte
	for remaining := len(data); remaining != 0; {
		if next.count == 0 {
			if next.buffer&ip12DMAEnd != 0 || !next.descriptor(pic) || next.count == 0 {
				d.control &^= ip12DMAActive
				return false
			}
		}
		addr := next.buffer & ip12DMAAddress
		size := min(next.count, uint32(remaining))
		mem := pic.memory(addr, size)
		if mem == nil || size > ip12DMAAddress-addr+1 {
			d.control &^= ip12DMAActive
			return false
		}
		spans = append(spans, mem)
		next.count -= size
		next.buffer = next.buffer&ip12DMAEnd | (addr+size)&ip12DMAAddress
		remaining -= int(size)
	}
	for _, mem := range spans {
		if toRAM {
			copy(mem, data[:len(mem)])
		} else {
			copy(data, mem)
		}
		data = data[len(mem):]
	}
	next.control &^= ip12DMAActive
	*d = next
	return true
}

func (m *IP12) hpcSCSI(address, value uint32, write bool) uint32 {
	d := &m.dma
	var reg *uint32
	switch address {
	case 0x1fb80088:
		reg = &d.count
		value &= 0x1fff
	case 0x1fb8008c:
		reg = &d.buffer
		value &= ip12DMAAddress | ip12DMAEnd
	case 0x1fb80090:
		if write {
			d.next = value & ip12DMAAddress
			if !d.descriptor(&m.pic) {
				d.count = 0
				d.control &^= ip12DMAActive
			}
		}
		return d.next
	case 0x1fb80094:
		if write {
			d.control = value & (ip12DMAActive | ip12DMAToRAM)
			if value&1 != 0 {
				m.scsi = wd33c93{} // External reset clears the interrupt line.
			}
			m.scsi.dma(m)
		}
		return d.control
	case 0x1fb80098:
		return 0 // The synchronous DMA FIFO is empty between transfers.
	default:
		return 0
	}
	if write {
		*reg = value
	}
	return *reg
}

// The auxiliary register carries the 93C56 Microwire signals. Words are
// shifted out most-significant bit first and reads can continue sequentially.
type ip12EEPROM struct {
	words                         [128]uint16
	pins, count, writeCommand     byte
	shift                         uint16
	address                       byte
	dataOut, reading, writeEnable bool
}

func (n *ip12EEPROM) access(value byte, write bool) uint32 {
	if !write {
		return uint32(n.pins&^0x10) | truth(n.dataOut)<<4
	}
	old := n.pins
	n.pins = value &^ 0x10
	if value&2 == 0 {
		n.count, n.shift, n.writeCommand = 0, 0, 0
		n.dataOut, n.reading = true, false
		return 0
	}
	if old&4 != 0 || value&4 == 0 {
		return 0
	}
	if n.reading {
		n.count--
		n.dataOut = n.words[n.address]&(1<<n.count) != 0
		if n.count == 0 {
			n.address = (n.address + 1) & 127
			n.count = 16
		}
		return 0
	}
	bit := (value >> 3) & 1
	if n.writeCommand == 0 && n.count == 0 && bit == 0 {
		return 0 // Wait for the start bit.
	}
	n.shift = n.shift<<1 | uint16(bit)
	n.count++
	if n.writeCommand != 0 {
		if n.count == 16 {
			if n.writeEnable {
				if n.writeCommand == 1 {
					n.words[n.address] = n.shift
				} else {
					for i := range n.words {
						n.words[i] = n.shift
					}
				}
			}
			n.dataOut = true
		}
		return 0
	}
	if n.count != 10 {
		return 0
	}
	n.address = byte(n.shift & 127)
	switch n.shift >> 7 & 3 {
	case 0:
		switch n.address >> 5 {
		case 0:
			n.writeEnable = false
		case 1:
			n.count, n.writeCommand = 0, 2
		case 2:
			if n.writeEnable {
				for i := range n.words {
					n.words[i] = 0xffff
				}
			}
		case 3:
			n.writeEnable = true
		}
	case 1:
		n.count, n.writeCommand = 0, 1
	case 2:
		n.count, n.dataOut, n.reading = 16, false, true
	case 3:
		if n.writeEnable {
			n.words[n.address] = 0xffff
		}
	}
	return 0
}

func (n *ip12EEPROM) init() {
	for i := range n.words {
		n.words[i] = 0xffff
	}
	n.dataOut = true
	// 4D/35 address PROM layout places the six station bytes at byte 122.
	for i := 0; i < len(ip12EthernetAddress)/2; i++ {
		n.words[61+i] = binary.BigEndian.Uint16(ip12EthernetAddress[2*i:])
	}
}
