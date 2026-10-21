package cc

import (
	"encoding/binary"
	"j5.nz/cc/hypervisor/x86state"
)

const biosMousePort = 0xf3
const biosMouseData = 0xf2400

type biosMouse struct {
	index  int
	packet [3]byte
}

func (p *pc) installMouseFirmware() {
	// The C2 service's successful enable/disable tail programs the actual PIC
	// through guest instructions, so native and interpreted CPUs see identical
	// masks. Other INT15 functions return without touching the mouse IRQ.
	code := []byte{0x80, 0xfc, 0xc2, 0x75, 0x7b, 0xe6, biosPort, 0x50, 0x80, 0xfc, 0, 0x75, 0, 0x3c, 0, 0x75, 0, 0x80, 0xff, 1, 0x74, 0, 0x80, 0xff, 0, 0x75, 0, 0xe4, 0xa1, 0x0c, 0x10, 0xe6, 0xa1, 0xeb, 0}
	enable := len(code)
	code = append(code, 0xe4, 0xa1, 0x24, 0xef, 0xe6, 0xa1, 0xe4, 0x21, 0x24, 0xfb, 0xe6, 0x21)
	done := len(code)
	code = append(code, 0x58, 0xcf)
	for _, j := range []int{12, 16, 26, 34} {
		code[j] = byte(done - j - 1)
	}
	code[21] = byte(enable - 22)
	copy(p.ram[0xf2500:], code)
	copy(p.ram[0xf2580:], []byte{0xe6, biosPort, 0xcf})
	binary.LittleEndian.PutUint16(p.ram[0x15*4:], 0x2500)
	// IRQ12 dispatches one complete three-byte PS/2 packet as a real far call
	// with status, X, Y, Z words on the caller's stack. Save the full 32-bit
	// register file and all data segments across the installed callback.
	irq := []byte{0x66, 0x60, 0x1e, 0x06, 0x0f, 0xa0, 0x0f, 0xa8, 0xe4, 0x64, 0xa8, 0x20, 0x74, 0, 0xe4, 0x60, 0xe6, biosMousePort, 0x2e, 0x80, 0x3e, 0x0c, 0x24, 0, 0x74, 0, 0x2e, 0xc6, 0x06, 0x0c, 0x24, 0}
	for _, off := range []byte{0, 2, 4, 6} {
		irq = append(irq, 0x2e, 0xff, 0x36, off, 0x24)
	}
	irq = append(irq, 0xfb, 0x2e, 0xff, 0x1e, 8, 0x24, 0xfa, 0x83, 0xc4, 8)
	ack := len(irq)
	irq = append(irq, 0xb0, 0x20, 0xe6, 0xa0, 0xe6, 0x20, 0x0f, 0xa9, 0x0f, 0xa1, 0x07, 0x1f, 0x66, 0x61, 0xcf)
	irq[13] = byte(ack - 14)
	irq[25] = byte(ack - 26)
	copy(p.ram[0xf2300:], irq)
	binary.LittleEndian.PutUint16(p.ram[0x74*4:], 0x2300)
}
func (p *pc) mouseBIOS(r *x86state.Registers, s x86state.SystemRegisters) byte {
	p.beforeRAMWrite(biosMouseData, 13)
	k := p.keyboard
	bh := byte(r.Rbx >> 8)
	reset := func() {
		k.mouseEnabled = false
		k.mouseRemote = false
		k.mouseScaling = false
		k.mouseRate = 100
		k.mouseResolution = 2
		k.mouseButtons = 0
		p.biosMouse.index = 0
	}
	switch byte(r.Rax) {
	case 0:
		if bh > 1 {
			return 1
		}
		if bh == 1 && binary.LittleEndian.Uint32(p.ram[biosMouseData+8:]) == 0 {
			return 5
		}
		k.mouseEnabled = bh == 1
		if k.mouseEnabled {
			k.command = k.command&^0x20 | 2
		}
	case 1:
		reset()
		setLow(&r.Rbx, 0x00aa)
	case 2:
		rates := [...]byte{10, 20, 40, 60, 80, 100, 200}
		if int(bh) >= len(rates) {
			return 2
		}
		k.mouseRate = rates[bh]
	case 3:
		if bh > 3 {
			return 2
		}
		k.mouseResolution = bh
	case 4:
		r.Rbx &^= 0xff00
	case 5:
		if bh != 3 {
			return 3
		}
		reset()
		clear(p.ram[biosMouseData : biosMouseData+13])
		setLow(&r.Rbx, 0x00aa)
	case 6:
		switch bh {
		case 0:
			status := (k.mouseButtons&1)<<2 | (k.mouseButtons&2)>>1 | (k.mouseButtons&4)>>1
			if k.mouseEnabled {
				status |= 0x20
			}
			if k.mouseRemote {
				status |= 0x40
			}
			if k.mouseScaling {
				status |= 0x10
			}
			r.Rbx = r.Rbx&^255 | uint64(status)
			r.Rcx = r.Rcx&^255 | uint64(k.mouseResolution)
			r.Rdx = r.Rdx&^255 | uint64(k.mouseRate)
		case 1, 2:
			k.mouseScaling = bh == 2
		default:
			return 1
		}
	case 7:
		binary.LittleEndian.PutUint16(p.ram[biosMouseData+8:], uint16(r.Rbx))
		binary.LittleEndian.PutUint16(p.ram[biosMouseData+10:], s.Es.Selector)
		p.biosMouse.index = 0
		if uint16(r.Rbx) == 0 && s.Es.Selector == 0 {
			k.mouseEnabled = false
		}
	default:
		return 1
	}
	return 0
}
func (p *pc) biosMouseByte(v byte) {
	p.beforeRAMWrite(biosMouseData, 13)
	if binary.LittleEndian.Uint32(p.ram[biosMouseData+8:]) == 0 {
		p.biosMouse.index = 0
		return
	}
	m := &p.biosMouse
	if m.index == 0 && v&8 == 0 {
		return
	} // resynchronize on the packet header
	m.packet[m.index] = v
	m.index++
	if m.index < 3 {
		return
	}
	m.index = 0
	for i, v := range m.packet {
		binary.LittleEndian.PutUint16(p.ram[biosMouseData+i*2:], uint16(v))
	}
	binary.LittleEndian.PutUint16(p.ram[biosMouseData+6:], 0)
	p.ram[biosMouseData+12] = 1
}
