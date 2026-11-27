package r3000

import "encoding/binary"

const (
	mcDMACause   = 0x160 / 8
	mcDMAControl = 0x168 / 8
	mcDMATLB     = 0x180 / 8
	mcDMAIRQ     = 0x10
	mcDMAXlate   = 0x100
	mcDMARunning = 0x40

	mcDMAInvalidPage = 1
	mcDMATLBMiss     = 2
	mcDMACleanPage   = 4
	mcDMAComplete    = 8
)

// The MC graphics DMA engine drives a fixed GIO port through a
// stride-and-zoom descriptor. Its translation cache is separate from CP0.
type mcVDMA struct {
	memory, gio, size, stride, mode, count uint32
	deadline                               uint64
}

func (m *IP24) mcDMAReg(offset, value uint32, write bool) uint32 {
	d := &m.vdma
	var reg *uint32
	switch offset {
	case 0x2008:
		if write {
			d.defaults()
		}
		fallthrough
	case 0x2000:
		reg = &d.memory
	case 0x2010:
		if write {
			d.count = d.count&0x03ff0000 | value&0xffff
		}
		reg = &d.size
	case 0x2018:
		if write {
			d.count = value&0x03ff0000 | d.count&0xffff
		}
		reg = &d.stride
	case 0x2020, 0x2028, 0x2070:
		if write && offset != 0x2020 {
			if offset == 0x2070 {
				d.defaults()
			}
			d.start(m)
		}
		reg = &d.gio
	case 0x2030:
		reg = &d.mode
	case 0x2038:
		reg = &d.count
	case 0x2040:
		if write {
			if value&1 != 0 {
				d.start(m)
			} else {
				d.deadline = 0
			}
		}
		return 0
	case 0x2048:
		return m.mc[mcDMACause] | truth(d.deadline != 0)*mcDMARunning
	default:
		return 0
	}
	if write {
		*reg = value
	}
	return *reg
}

func (d *mcVDMA) defaults() {
	d.size, d.stride, d.mode, d.count = 0x1000c, 0x10000, 0x28, 0x1000c
}

func (d *mcVDMA) start(m *IP24) {
	d.deadline = m.cycles + 20
	if d.mode&4 != 0 && m.newport != nil {
		d.deadline = max(d.deadline, m.newport.nextRetrace)
	}
}

func (m *IP24) vdmaPhysical(address uint32, store bool) (uint32, uint32) {
	control := m.mc[mcDMAControl]
	if control&mcDMAXlate == 0 {
		return address, 0
	}
	pageShift := 12 + 2*(control>>1&1)
	pteShift := 2 + (control & 1)
	regionShift := 2*pageShift - pteShift
	lowMask := uint32(1)<<regionShift - 1
	for i := range 4 {
		hi, lo := m.mc[mcDMATLB+2*i], m.mc[mcDMATLB+2*i+1]
		if (address^hi)&^lowMask != 0 || lo&2 == 0 {
			continue
		}
		pteBase := (lo & 0x03ffffc0) << 6
		index := (address & lowMask) >> pageShift
		pteAddress := pteBase + (index << pteShift)
		if pteShift == 3 {
			pteAddress += 4 // Low word of a big-endian 64-bit PTE.
		}
		data := m.memory(uint64(pteAddress), 4)
		if data == nil {
			return 0, mcDMAInvalidPage
		}
		pte := binary.BigEndian.Uint32(data)
		if pte&2 == 0 {
			return 0, mcDMAInvalidPage
		}
		if store && pte&4 == 0 {
			return 0, mcDMACleanPage
		}
		pageMask := uint32(1)<<pageShift - 1
		pageBase := (pte & 0x03ffffc0) << 6 &^ pageMask
		return pageBase | (address & pageMask), 0
	}
	return 0, mcDMATLBMiss
}

func (m *IP24) tickVDMA() {
	d := &m.vdma
	if d.deadline == 0 || m.cycles < d.deadline {
		return
	}
	toMemory, fill := d.mode&2 != 0, d.mode&0xa == 0xa
	step := uint32(1)
	if d.mode&0x10 == 0 {
		step = ^uint32(0)
	}
	mask, substitute := m.mc[0x150/8], m.mc[0x158/8]
	gio := uint64((d.gio&^mask | substitute&mask) & 0x1fffffff)
	for range 64 {
		if d.size>>16 == 0 {
			m.finishVDMA(mcDMAComplete)
			return
		}
		remaining := d.count & 0xffff
		if remaining == 0 || d.count>>16&0x3ff == 0 {
			d.advanceLine(step)
			continue
		}
		length := min(remaining, uint32(8))
		if fill {
			length = min(remaining, uint32(4))
		}
		var locations [8][]byte
		for i := range length {
			physical, fault := m.vdmaPhysical(d.memory+i*step, toMemory)
			if fault != 0 {
				m.finishVDMA(fault)
				return
			}
			locations[i] = m.memory(uint64(physical), 1)
			if locations[i] == nil {
				m.finishVDMA(mcDMAInvalidPage)
				return
			}
		}
		if !m.vdmaWord(gio, locations[:length], toMemory, fill) {
			m.mc[0xf0/8], m.mc[0xf8/8] = uint32(gio), 0x400
			m.finishVDMA(mcDMAInvalidPage)
			return
		}
		d.memory += length * step
		d.count -= length
	}
	d.deadline = m.cycles + 64*5
}

func (d *mcVDMA) advanceLine(step uint32) {
	width := d.size & 0xffff
	zoom := d.count >> 16 & 0x3ff
	if zoom > 1 {
		d.memory -= width * step
		d.count = (zoom-1)<<16 | width
		return
	}
	d.memory += uint32(int32(int16(d.stride)))
	d.size -= 0x10000
	d.count = d.stride&0x03ff0000 | width
}

func (m *IP24) vdmaWord(gio uint64, locations [][]byte, toMemory, fill bool) bool {
	if toMemory {
		data, ok := uint64(m.vdma.gio)<<32, true
		if !fill {
			data, ok = m.read64(gio, 8)
		}
		if !ok {
			return false
		}
		for i, p := range locations {
			p[0] = byte(data >> (56 - 8*i))
		}
		return true
	}
	var data uint64
	for i, p := range locations {
		data |= uint64(p[0]) << (56 - 8*i)
	}
	return m.write64(gio, 8, data)
}

func (m *IP24) finishVDMA(cause uint32) {
	m.vdma.deadline = 0
	m.mc[mcDMACause] |= cause
}
