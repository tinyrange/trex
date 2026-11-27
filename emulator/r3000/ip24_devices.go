package r3000

import (
	"encoding/binary"

	"github.com/tinyrange/trex/scsi"
)

const (
	hpc3ToDevice = 0x04
	hpc3Flush    = 0x08
	hpc3Active   = 0x10
	hpc3Reset    = 0x40
	hpc3EOX      = 1 << 31
	hpc3IRQ      = 1 << 29
	hpc3Count    = 0x3fff
)

type hpc3SCSI struct {
	buffer, next, count, flags, control uint32
	dmaConfig, pioConfig                uint32
	interrupt                           bool
}

// PBUS control and descriptor registers are present even when no
// peripheral is requesting transfers on the channel.
type hpc3PBUS struct {
	buffer, descriptor, control uint32
}

func (m *IP24) hpcPBUS(offset, value uint32, write bool) uint32 {
	channel := &m.pbusDMA[offset>>13]
	switch offset & 0x1fff {
	case 0:
		return channel.buffer
	case 4:
		if write {
			channel.descriptor = value
			if data := m.memory(uint64(value), 4); data != nil && value&3 == 0 {
				channel.buffer = binary.BigEndian.Uint32(data)
			}
		}
		return channel.descriptor
	case 0x1000:
		if write {
			active := channel.control & hpc3Active
			if value&0x20 != 0 {
				active = value & hpc3Active
			}
			channel.control = value&^hpc3Active | active
		}
		return (channel.control & hpc3Active) >> 3
	}
	return 0
}

func (m *IP24) scsiTarget(target byte) *scsi.Disk {
	return m.targets[target]
}

func (m *IP24) scsiDMAEnabled(toRAM bool) bool {
	return m.dma.control&hpc3Active != 0 && (m.dma.control&hpc3ToDevice == 0) == toRAM
}

func (m *IP24) scsiTransfer(data []byte, toRAM bool) bool {
	d := m.dma
	type span struct {
		address uint32
		size    int
	}
	var spans []span
	for left := len(data); left != 0; {
		if d.count == 0 {
			if d.flags&hpc3EOX != 0 || !d.fetch(m) {
				m.dma.control &^= hpc3Active
				return false
			}
		}
		n := min(int(d.count), left)
		if m.memory(uint64(d.buffer), uint64(n)) == nil {
			m.dma.control &^= hpc3Active
			return false
		}
		spans = append(spans, span{d.buffer, n})
		left -= n
		d.buffer, d.count = d.buffer+uint32(n), d.count-uint32(n)
		if d.count == 0 && d.flags&hpc3IRQ != 0 {
			d.interrupt = true
		}
	}
	for _, s := range spans {
		if d.control&2 == 0 {
			mem := m.memory(uint64(s.address), uint64(s.size))
			if toRAM {
				copy(mem, data[:s.size])
			} else {
				copy(data, mem)
			}
		} else {
			// Little-endian DMA reverses byte lanes within each word.
			for i := range s.size {
				mem := m.memory(uint64((s.address+uint32(i))^3), 1)
				if toRAM {
					mem[0] = data[i]
				} else {
					data[i] = mem[0]
				}
			}
		}
		data = data[s.size:]
	}
	if d.count == 0 && d.flags&hpc3EOX != 0 {
		d.control &^= hpc3Active
	}
	m.dma = d
	return true
}

func (d *hpc3SCSI) fetch(m *IP24) bool {
	p := m.memory(uint64(d.next), 12)
	if p == nil || d.next&3 != 0 {
		return false
	}
	d.buffer = binary.BigEndian.Uint32(p)
	d.flags = binary.BigEndian.Uint32(p[4:])
	d.next = binary.BigEndian.Uint32(p[8:])
	d.count = d.flags & hpc3Count
	return d.count != 0
}

func (m *IP24) hpcSCSI(offset, value uint32, write bool) uint32 {
	d := &m.dma
	var reg *uint32
	switch offset {
	case 0:
		return d.buffer
	case 4:
		reg = &d.next
	case 0x1000:
		if write {
			d.flags, d.count = value&^hpc3Count, value&hpc3Count
		}
		return d.flags | d.count
	case 0x1004:
		if write {
			old := d.control
			d.control = value & 0xfe
			if value&0x20 != 0 {
				d.control = d.control&^hpc3Active | old&hpc3Active
			}
			if value&hpc3Reset != 0 {
				m.scsi = wd33c93{modelB: true}
			}
			if old&hpc3Active == 0 && d.control&hpc3Active != 0 {
				d.flags, d.count = 0, 0
				if !d.fetch(m) {
					d.control &^= hpc3Active
				}
			}
			m.scsi.dma(m)
			if value&hpc3Flush != 0 {
				d.control &^= hpc3Active | hpc3Flush
			}
		}
		result := d.control | truth(d.interrupt)
		if !write {
			d.interrupt = false
		}
		return result
	case 0x1010:
		reg = &d.dmaConfig
	case 0x1014:
		reg = &d.pioConfig
	default:
		return 0
	}
	if write {
		*reg = value
	}
	return *reg
}

func (m *IP24) updateInterrupts() {
	m.tickVDMA()
	m.int3.updatePIT(m.cycles / (ip24Clock / 1_000_000))
	m.keyboard.tick(m.cycles)
	m.int3.reg[4] = byte(truth(m.scc.irq())<<5 | truth(m.keyboard.irq(false) || m.keyboard.irq(true))<<4)
	m.int3.reg[0] = byte(truth(m.scsi.irq)<<1 | truth(m.int3.reg[4]&m.int3.reg[5] != 0)<<7)
	if m.mc[mcDMACause]&7 != 0 || m.mc[mcDMACause]&mcDMAComplete != 0 && m.mc[mcDMAControl]&mcDMAIRQ != 0 {
		m.int3.reg[0] |= 0x10
	}
	m.int3.reg[2] = byte(truth(m.dma.interrupt)<<4 | truth(m.int3.reg[4]&m.int3.reg[6] != 0)<<3)
	if m.newport != nil {
		m.newport.tick(m.cycles)
		m.int3.reg[2] |= byte(truth(m.newport.retrace) << 7)
	}
	unsigned := truth(m.int3.reg[0]&m.int3.reg[1] != 0)<<10 | truth(m.int3.reg[2]&m.int3.reg[3] != 0)<<11 |
		uint32(m.int3.pending)<<12
	m.cpu.cp0[cause] = m.cpu.cp0[cause]&^0x3c00 | uint64(unsigned)
}

func (m *IP24) io(address uint64, size, data uint32, write bool) (uint64, bool) {
	if address > 0x1fffffff {
		return 0, false
	}
	a := uint32(address)
	switch {
	case a >= 0x1f000000 && a < 0x1fa00000:
		// The empty GIO slots have no read responder. Writes are posted
		// by the MC, including writes used to probe for Newport.
		return 0, write
	case a >= ip24MC && a < ip24MC+0x200 && a&7 == 4 && size == 4:
		index := (a - ip24MC) / 8
		if write && index != 3 {
			m.mc[index] = data
			if index == 2 || index == 0xec/8 || index == 0xfc/8 {
				m.mc[index] = 0
			}
		}
		return uint64(m.mc[index]), true
	case (a == ip24MC+0x1004 || a == ip24MC+0x1000) && size == 4 && !write:
		return uint64(uint32(m.cycles / (ip24Clock / 10_000_000))), true
	case a >= ip24MC+0x2000 && a < ip24MC+0x2078 && a&3 == 0 && size == 4:
		return uint64(m.mcDMAReg((a-ip24MC)&^4, data, write)), true
	case a >= ip24HPC && a < ip24HPC+0x10000 && size == 4:
		return uint64(m.hpcPBUS(a-ip24HPC, data, write)), true
	case a >= ip24HPC+0x10000 && a < ip24HPC+0x12000 && size == 4:
		return uint64(m.hpcSCSI(a-ip24HPC-0x10000, data, write)), true
	case a >= ip24HPC+0x14000 && a < ip24HPC+0x1c000 && size == 4:
		return uint64(m.ethernet.hpc(a-ip24HPC-0x14000, data, write)), true
	case a >= ip24HPC+0x54000 && a < ip24HPC+0x54020 && lowByteLane(a, size):
		return uint64(m.ethernet.seeq((a-ip24HPC-0x54000)/4, byte(data), write)), true
	case (a == ip24HPC+0x30000 || a == ip24HPC+0x3000c) && size == 4:
		return uint64(truth(m.dma.interrupt) << 8), !write
	case a == ip24HPC+0x30010 && size == 4 && !write:
		return 0, true // HPC3 bus-error status: no DMA or PBUS parity fault.
	case a == ip24IOC+0x100 && size == 4 && !write:
		return 0, true // External I/O inputs. No expansion signals asserted.
	case a&^3 == ip24HPC+0x30004 && size <= 4:
		if write && lowByteLane(a, size) {
			m.gioMisc = data & 3
		}
		return uint64(m.gioMisc >> ((4 - (a & 3) - size) * 8)), true
	case a >= ip24HPC+0x30008 && a < ip24HPC+0x3000c && lowByteLane(a, size):
		return uint64(m.eeprom.access(byte(data), write)), true
	case a >= 0x1fbc8000 && a < 0x1fbc8008 && lowByteLane(a, size):
		return 0xff, true // Indy has no device on HPC3 SCSI channel 1.
	case a >= 0x1fbc0000 && a < 0x1fbc0008 && lowByteLane(a, size):
		return uint64(m.scsi.port(m, a&4 != 0, byte(data), write)), true
	case a == ip24HPC+0x58020 && size == 4 && !write:
		return 0x8000, true // HAL2 revision register: no audio attached.
	case a >= ip24IOC && a < ip24IOC+0xc0 && lowByteLane(a, size):
		return m.iocAccess((a-ip24IOC)/4, byte(data), write)
	case a >= ip24HPC+0x5c000 && a < ip24HPC+0x5d000 && size == 4:
		index := (a - ip24HPC - 0x5c000) >> 9
		if write {
			m.pbusConfig[index] = data
		}
		return uint64(m.pbusConfig[index]), true
	case a >= ip24HPC+0x5d000 && a < ip24HPC+0x5e000 && size == 4:
		index := (a - ip24HPC - 0x5d000) >> 8
		if write {
			m.pioConfig[index] = data
		}
		return uint64(m.pioConfig[index]), true
	case a >= ip24HPC+0x60000 && a < ip24HPC+0x80000 && lowByteLane(a, size):
		return uint64(m.rtcAccess(uint64((a-ip24HPC-0x60000)/4), byte(data), write)), true
	}
	return 0, false
}

func lowByteLane(address, size uint32) bool {
	return size <= 4 && address&3+size == 4
}

func (m *IP24) iocAccess(index uint32, data byte, write bool) (uint64, bool) {
	switch {
	case index >= 0x20:
		value, ok := m.int3.access(index-0x20, data, write)
		return uint64(value), ok
	case index >= 0x0c && index <= 0x0f:
		// IOC2 exposes B control/data followed by A control/data.
		return uint64(m.scc.access(index-0x0c, data, write)), true
	case index == 0x10 || index == 0x11:
		return uint64(m.keyboard.access(m.cycles, index-0x10, data, write)), true
	case index == 0x16 || index == 0x18:
		return uint64(m.ioc[index]), !write
	case index < 0x20:
		if write {
			m.ioc[index] = data
		}
		return uint64(m.ioc[index]), true
	}
	return 0, false
}
