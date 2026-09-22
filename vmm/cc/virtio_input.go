package cc

import (
	"encoding/binary"
	"fmt"

	"j5.nz/cc/hypervisor"
)

const inputAddress = 0xe2000000
const inputIRQ = 10
const inputQueueMax = 128

type inputEvent struct {
	typ, code uint16
	value     uint32
}
type inputQueue struct {
	size              uint32
	ready             bool
	desc, avail, used uint64
	last, written     uint16
}

// virtioInput implements the modern virtio-MMIO transport and the virtio-input
// absolute pointer. All accesses run on the owning CPU loop. DMA can address
// ordinary guest RAM only; neither host buffers nor device apertures are DMA.
type virtioInput struct {
	memory                                                      func(uint64, uint64) ([]byte, error)
	irq                                                         func(uint32, bool) error
	status, interrupt, featureSelect, driverSelect, queueSelect uint32
	features                                                    [2]uint32
	queues                                                      [2]inputQueue
	selectID, subselect                                         byte
	pending                                                     [][]inputEvent
	buttons                                                     byte
	x, y                                                        uint32
	reports                                                     uint64
}

func (v *virtioInput) active() bool { return v.status&0xcf == 15 && v.queues[0].ready }
func (v *virtioInput) config() [136]byte {
	var c [136]byte
	c[0], c[1] = v.selectID, v.subselect
	data := c[8:]
	switch v.selectID {
	case 1:
		if v.subselect == 0 {
			c[2] = byte(copy(data, "TinyRangeX absolute pointer"))
		}
	case 2:
		if v.subselect == 0 {
			c[2] = byte(copy(data, "trex-pointer-0"))
		}
	case 3:
		if v.subselect == 0 {
			c[2] = 8
			binary.LittleEndian.PutUint16(data, 6)
			binary.LittleEndian.PutUint16(data[2:], 0x1af4)
			binary.LittleEndian.PutUint16(data[4:], 18)
			binary.LittleEndian.PutUint16(data[6:], 1)
		}
	case 0x10:
		if v.subselect == 0 {
			c[2], data[0] = 1, 1
		}
	case 0x11:
		switch v.subselect {
		case 0:
			c[2], data[0] = 1, 1 // EV_SYN / SYN_REPORT
		case 1:
			c[2], data[0x110/8] = 35, 7 // EV_KEY: left/right/middle
		case 2:
			c[2], data[1] = 2, 1 // EV_REL / REL_WHEEL
		case 3:
			c[2], data[0] = 1, 3 // EV_ABS / ABS_X,Y
		}
	case 0x12:
		if v.subselect < 2 {
			c[2] = 20
			binary.LittleEndian.PutUint32(data[4:], 65535)
		}
	}
	return c
}

func (v *virtioInput) read(offset uint64) uint32 {
	var q inputQueue
	if v.queueSelect < 2 {
		q = v.queues[v.queueSelect]
	}
	switch offset {
	case 0:
		return 0x74726976
	case 4:
		return 2
	case 8:
		return 18
	case 12:
		return 0x545258
	case 0x10:
		if v.featureSelect == 1 {
			return 1
		}
	case 0x34:
		if v.queueSelect < 2 {
			return inputQueueMax
		}
	case 0x44:
		if q.ready {
			return 1
		}
	case 0x60:
		return v.interrupt
	case 0x70:
		return v.status
	}
	return 0
}

func (v *virtioInput) write(offset uint64, value uint32) error {
	if offset == 0x70 && value == 0 {
		memory, irq := v.memory, v.irq
		*v = virtioInput{memory: memory, irq: irq}
		return v.irq(inputIRQ, false)
	}
	var q *inputQueue
	if v.queueSelect < 2 {
		q = &v.queues[v.queueSelect]
	}
	switch offset {
	case 0x14:
		v.featureSelect = value
	case 0x24:
		v.driverSelect = value
	case 0x20:
		if v.driverSelect < 2 && v.status&8 == 0 {
			v.features[v.driverSelect] = value
		}
	case 0x30:
		v.queueSelect = value
	case 0x38:
		if q != nil && !q.ready {
			q.size = value
		}
	case 0x44:
		if q != nil && value == 1 && !q.ready {
			if q.size == 0 || q.size > inputQueueMax || q.size&(q.size-1) != 0 || q.desc%16 != 0 || q.avail%2 != 0 || q.used%4 != 0 {
				return v.fail()
			}
			for _, r := range [][2]uint64{{q.desc, uint64(q.size) * 16}, {q.avail, 4 + uint64(q.size)*2}, {q.used, 4 + uint64(q.size)*8}} {
				if _, err := v.memory(r[0], r[1]); err != nil {
					return v.fail()
				}
			}
			q.ready = true
		} else if q != nil && value == 0 {
			q.ready = false
		}
	case 0x50:
		if value > 1 {
			return v.fail()
		}
		if value == 1 {
			return v.flushStatus()
		}
		return v.flush()
	case 0x64:
		v.interrupt &^= value
		return v.irq(inputIRQ, v.interrupt != 0)
	case 0x70:
		v.status = value
		if value&8 != 0 && (v.features[0] != 0 || v.features[1] != 1) {
			v.status &^= 8
		}
	case 0x80, 0x84, 0x90, 0x94, 0xa0, 0xa4:
		if q != nil && !q.ready {
			address := &q.desc
			if offset&0xf0 == 0x90 {
				address = &q.avail
			} else if offset&0xf0 == 0xa0 {
				address = &q.used
			}
			if offset&4 == 0 {
				*address = *address&0xffffffff00000000 | uint64(value)
			} else {
				*address = uint64(value)<<32 | *address&0xffffffff
			}
		}
	}
	return nil
}

func (v *virtioInput) fail() error { v.status |= 64; v.interrupt |= 2; return v.irq(inputIRQ, true) }

func (v *virtioInput) mmio(ex hypervisor.X86Exit, cpu hypervisor.X86) error {
	offset := ex.Address - inputAddress
	if ex.Size == 0 || ex.Size > 4 || offset+uint64(ex.Size) > 0x1000 || (ex.Write && len(ex.Data) < int(ex.Size)) {
		return v.fail()
	}
	if offset >= 0x100 {
		if ex.Write {
			for i := uint64(0); i < uint64(ex.Size); i++ {
				if offset+i == 0x100 {
					v.selectID = ex.Data[i]
				}
				if offset+i == 0x101 {
					v.subselect = ex.Data[i]
				}
			}
		} else {
			c := v.config()
			var value uint32
			for i := uint64(0); i < uint64(ex.Size); i++ {
				if offset+i < 0x188 {
					value |= uint32(c[offset+i-0x100]) << (8 * i)
				}
			}
			cpu.CompleteMMIORead(uint64(value), uint32(ex.Size))
		}
		return nil
	}
	if ex.Size != 4 || offset%4 != 0 {
		return v.fail()
	}
	if ex.Write {
		return v.write(offset, binary.LittleEndian.Uint32(ex.Data))
	}
	cpu.CompleteMMIORead(uint64(v.read(offset)), uint32(ex.Size))
	return nil
}

// destinations validates the entire writable descriptor chain before DMA.
func (v *virtioInput) buffers(q *inputQueue, head uint16, writable bool) ([][]byte, error) {
	var parts [][]byte
	total := uint64(0)
	for count := uint32(0); count < q.size; count++ {
		if uint32(head) >= q.size {
			break
		}
		d, err := v.memory(q.desc+uint64(head)*16, 16)
		if err != nil {
			return nil, err
		}
		flags, next := binary.LittleEndian.Uint16(d[12:]), binary.LittleEndian.Uint16(d[14:])
		if flags&^uint16(3) != 0 || (flags&2 != 0) != writable {
			break
		}
		length := uint64(binary.LittleEndian.Uint32(d[8:]))
		address := binary.LittleEndian.Uint64(d)
		part, err := v.memory(address, length)
		if err != nil {
			return nil, err
		}
		if total < 8 {
			parts = append(parts, part[:min(length, 8-total)])
		}
		total += length
		if flags&1 == 0 {
			if total >= 8 {
				return parts, nil
			}
			break
		}
		head = next
	}
	return nil, fmt.Errorf("invalid virtio-input event descriptor chain")
}

func (v *virtioInput) flush() error {
	if !v.active() {
		return nil
	}
	q := &v.queues[0]
	avail, _ := v.memory(q.avail, 4+uint64(q.size)*2)
	used, _ := v.memory(q.used, 4+uint64(q.size)*8)
	for len(v.pending) != 0 {
		count := uint16(binary.LittleEndian.Uint16(avail[2:]) - q.last)
		if uint32(count) > q.size {
			return v.fail()
		}
		report := v.pending[0]
		if int(count) < len(report) {
			break
		}
		var buffers [][][]byte
		var heads []uint16
		for i := range report {
			head := binary.LittleEndian.Uint16(avail[4+2*((uint32(q.last)+uint32(i))%q.size):])
			parts, err := v.buffers(q, head, true)
			if err != nil {
				return v.fail()
			}
			buffers = append(buffers, parts)
			heads = append(heads, head)
		}
		for i, event := range report {
			var data [8]byte
			binary.LittleEndian.PutUint16(data[:], event.typ)
			binary.LittleEndian.PutUint16(data[2:], event.code)
			binary.LittleEndian.PutUint32(data[4:], event.value)
			at := 0
			for _, part := range buffers[i] {
				at += copy(part, data[at:])
			}
			slot := 4 + 8*(uint32(q.written)%q.size)
			binary.LittleEndian.PutUint32(used[slot:], uint32(heads[i]))
			binary.LittleEndian.PutUint32(used[slot+4:], 8)
			q.written++
			q.last++
		}
		binary.LittleEndian.PutUint16(used[2:], q.written)
		v.pending = v.pending[1:]
		v.reports++
		if binary.LittleEndian.Uint16(avail)&1 == 0 {
			v.interrupt |= 1
		}
	}
	return v.irq(inputIRQ, v.interrupt != 0)
}

// No status-event capabilities (such as LEDs) are advertised. Consume valid
// status buffers and ignore unsupported events as required by virtio-input.
func (v *virtioInput) flushStatus() error {
	q := &v.queues[1]
	if !v.active() || !q.ready {
		return nil
	}
	avail, _ := v.memory(q.avail, 4+uint64(q.size)*2)
	used, _ := v.memory(q.used, 4+uint64(q.size)*8)
	count := uint16(binary.LittleEndian.Uint16(avail[2:]) - q.last)
	if uint32(count) > q.size {
		return v.fail()
	}
	for i := uint16(0); i < count; i++ {
		head := binary.LittleEndian.Uint16(avail[4+2*(uint32(q.last)%q.size):])
		if _, err := v.buffers(q, head, false); err != nil {
			return v.fail()
		}
		slot := 4 + 8*(uint32(q.written)%q.size)
		binary.LittleEndian.PutUint32(used[slot:], uint32(head))
		binary.LittleEndian.PutUint32(used[slot+4:], 0)
		q.last++
		q.written++
	}
	binary.LittleEndian.PutUint16(used[2:], q.written)
	if count != 0 && binary.LittleEndian.Uint16(avail)&1 == 0 {
		v.interrupt |= 1
	}
	return v.irq(inputIRQ, v.interrupt != 0)
}

func (v *virtioInput) pointer(x, y uint32, buttons byte, wheel int32) error {
	if !v.active() {
		return fmt.Errorf("virtio-input driver is not ready")
	}
	if len(v.pending) >= 64 {
		return fmt.Errorf("virtio-input queue is full")
	}
	events := []inputEvent{{3, 0, x}, {3, 1, y}}
	for i := uint16(0); i < 3; i++ {
		if (buttons^v.buttons)&(1<<i) != 0 {
			events = append(events, inputEvent{1, 0x110 + i, uint32((buttons >> i) & 1)})
		}
	}
	if wheel != 0 {
		events = append(events, inputEvent{2, 8, uint32(wheel)})
	}
	events = append(events, inputEvent{})
	v.pending = append(v.pending, events)
	v.buttons = buttons
	v.x = x
	v.y = y
	return v.flush()
}
