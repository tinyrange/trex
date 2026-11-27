package r3000

import "encoding/binary"

const (
	ip12GDMARegisters   = 0x1faa0000
	ip12GDMAStart       = 0x1faa0100
	ip12GDMAAddressMask = 0x0fffffff
	ip12GDMAEnd         = 1 << 15
	ip12GDMAFullPage    = 1 << 30
	ip12GDMADirection   = 3 << 12
	ip12GDMAToRAM       = 2 << 12
)

type ip12GraphicsDMA struct {
	base, next                  uint32
	buffer, length, destination uint32
	stride                      uint32
	line, width, lines, offset  uint32
	descriptors                 uint32
	active, done, failed        bool
	words                       uint64
}

func (d *ip12GraphicsDMA) start(pic *ip12PIC) {
	d.next = d.base & ip12GDMAAddressMask
	d.descriptors, d.offset = 0, 0
	d.active, d.done, d.failed = true, false, false
	d.loadDescriptor(pic)
}

func (d *ip12GraphicsDMA) finish(failed bool) {
	d.active, d.done, d.failed = false, true, failed
}

func (d *ip12GraphicsDMA) loadDescriptor(pic *ip12PIC) {
	data := pic.memory(d.next, 20)
	if data == nil || d.next&3 != 0 || d.next&4095 > 4076 || d.descriptors == 4096 {
		d.finish(true)
		return
	}
	d.descriptors++
	d.buffer = binary.BigEndian.Uint32(data)
	d.length = binary.BigEndian.Uint32(data[4:])
	d.destination = binary.BigEndian.Uint32(data[8:])
	d.stride = binary.BigEndian.Uint32(data[12:])
	d.next = binary.BigEndian.Uint32(data[16:]) & ip12GDMAAddressMask
	d.width = d.length & 4095
	if d.length&ip12GDMAFullPage != 0 {
		d.width = 4096
	}
	d.lines = uint32(uint16(d.stride)) + 1
	d.line, d.offset = d.buffer, 0
	mode := d.length & ip12GDMADirection
	if d.width == 0 || d.width&3 != 0 || d.buffer&3 != 0 ||
		(mode != 0 && mode != ip12GDMAToRAM) ||
		(d.destination != 0 && d.destination != 0x1f000000) {
		d.finish(true)
	}
}

// word participates in a burst initiated by the GR1 microcode. Each successful
// HQ1 repeat consumes one RAM word and advances the PIC1 descriptor.
func (d *ip12GraphicsDMA) word(pic *ip12PIC, toRAM bool, value uint32) (uint32, bool) {
	if !d.active {
		return 0, false
	}
	memory := pic.memory(d.line+d.offset, 4)
	if memory == nil || toRAM != (d.length&ip12GDMADirection == ip12GDMAToRAM) {
		d.finish(true)
		return 0, false
	}
	if toRAM {
		binary.BigEndian.PutUint32(memory, value)
	} else {
		value = binary.BigEndian.Uint32(memory)
	}
	d.words++
	d.offset += 4
	if d.offset == d.width {
		d.lines--
		d.offset = 0
		switch {
		case d.lines != 0:
			d.line += d.width + uint32(int32(d.stride<<4)>>20)
		case d.length&ip12GDMAEnd != 0:
			d.finish(false)
		default:
			d.loadDescriptor(pic)
		}
	}
	return value, true
}

func (m *IP12) graphicsDMA(address, value uint32, write bool) (uint32, bool) {
	d := &m.gdma
	switch address {
	case ip12GDMARegisters:
		if write {
			d.base = value
		}
		return d.base, true
	case ip12GDMARegisters + 4:
		return d.buffer, !write
	case ip12GDMARegisters + 8:
		return d.length, !write
	case ip12GDMARegisters + 12:
		return d.destination, !write
	case ip12GDMARegisters + 16:
		return d.stride, !write
	case ip12GDMAStart:
		if write {
			d.start(&m.pic)
		}
		return 0, write
	}
	return 0, false
}
