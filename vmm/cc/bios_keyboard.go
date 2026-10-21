package cc

import (
	"encoding/binary"
	"j5.nz/cc/hypervisor/x86state"
)

// Firmware owns the AT BIOS buffer only while the guest uses our IRQ1 vector.
// Protected-mode guests install their own handler and read the i8042 directly.
func (p *pc) installKeyboardFirmware() {
	binary.LittleEndian.PutUint16(p.ram[9*4:], 0x2100)
	// Preserve AX, consume one translated byte, service it, acknowledge PIC.
	copy(p.ram[0xf2100:], []byte{0x50, 0xe4, 0x60, 0xe6, biosPort, 0xb0, 0x20, 0xe6, 0x20, 0x58, 0xcf})
	binary.LittleEndian.PutUint16(p.ram[0x16*4:], 0x2200)
	// A blocking read sleeps in guest firmware with IRQs enabled. The host
	// device loop stays available for input; no polling or host-side wait.
	copy(p.ram[0xf2200:], []byte{0xe6, biosPort, 0x75, 5, 0xfb, 0xf4, 0xfa, 0xeb, 0xf7, 0xcf})
	for _, addr := range []int{0x41a, 0x41c, 0x480} {
		binary.LittleEndian.PutUint16(p.ram[addr:], 0x1e)
	}
	binary.LittleEndian.PutUint16(p.ram[0x482:], 0x3e)
}

func (p *pc) keyboardBounds() (head, tail uint16) {
	head = binary.LittleEndian.Uint16(p.ram[0x41a:])
	tail = binary.LittleEndian.Uint16(p.ram[0x41c:])
	return
}
func nextKeyboardWord(offset uint16) uint16 {
	offset += 2
	if offset >= 0x3e {
		return 0x1e
	}
	return offset
}
func validKeyboardWord(offset uint16) bool { return offset >= 0x1e && offset < 0x3e && offset&1 == 0 }
func (p *pc) storeKeyboardWord(word uint16) bool {
	p.beforeRAMWrite(0x400, 0x100)
	head, tail := p.keyboardBounds()
	if !validKeyboardWord(head) || !validKeyboardWord(tail) || nextKeyboardWord(tail) == head {
		return false
	}
	binary.LittleEndian.PutUint16(p.ram[0x400+int(tail):], word)
	binary.LittleEndian.PutUint16(p.ram[0x41c:], nextKeyboardWord(tail))
	return true
}

// US layout for the translated set-1 keyboard. Values are BIOS scan/ASCII
// words, not Unicode; guest keyboard drivers may replace this firmware policy.
var biosKeyASCII = [128]byte{
	1: 27, 2: '1', 3: '2', 4: '3', 5: '4', 6: '5', 7: '6', 8: '7', 9: '8', 10: '9', 11: '0', 12: '-', 13: '=', 14: 8, 15: 9,
	16: 'q', 17: 'w', 18: 'e', 19: 'r', 20: 't', 21: 'y', 22: 'u', 23: 'i', 24: 'o', 25: 'p', 26: '[', 27: ']', 28: 13,
	30: 'a', 31: 's', 32: 'd', 33: 'f', 34: 'g', 35: 'h', 36: 'j', 37: 'k', 38: 'l', 39: ';', 40: '\'', 41: '`', 43: '\\',
	44: 'z', 45: 'x', 46: 'c', 47: 'v', 48: 'b', 49: 'n', 50: 'm', 51: ',', 52: '.', 53: '/', 55: '*', 57: ' ', 74: '-', 78: '+',
}

func (p *pc) keyboardScan(scan byte) {
	p.beforeRAMWrite(0x400, 0x100)
	if scan == 0xe0 {
		p.biosKeyExtended = true
		return
	}
	if scan == 0xe1 {
		p.biosKeyPause = 5
		return
	}
	if p.biosKeyPause != 0 {
		p.biosKeyPause--
		return
	}
	extended := p.biosKeyExtended
	p.biosKeyExtended = false
	released := scan&0x80 != 0
	scan &= 0x7f
	flags := &p.ram[0x417]
	var bit byte
	switch scan {
	case 0x2a:
		if !extended {
			bit = 2
		}
	case 0x36:
		if !extended {
			bit = 1
		}
	case 0x1d:
		bit = 4
	case 0x38:
		bit = 8
	case 0x3a:
		bit = 0x40
	case 0x45:
		bit = 0x20
	case 0x46:
		bit = 0x10
	}
	if bit != 0 {
		if bit < 16 {
			if released {
				*flags &^= bit
			} else {
				*flags |= bit
			}
		} else {
			// The second BDA flag byte records lock-key down state, so repeats do
			// not toggle a lock multiple times before its break code arrives.
			down := &p.ram[0x418]
			if released {
				*down &^= bit
			} else if *down&bit == 0 {
				*down |= bit
				*flags ^= bit
			}
		}
		return
	}
	if released || scan == 0 {
		return
	}
	ascii := biosKeyASCII[scan]
	if extended {
		ascii = 0xe0
		if scan == 0x1c {
			ascii = 13
		}
		if scan == 0x35 {
			ascii = '/'
		}
	} else if scan >= 0x47 && scan <= 0x53 && *flags&0x20 != 0 && *flags&3 == 0 {
		ascii = map[byte]byte{0x47: '7', 0x48: '8', 0x49: '9', 0x4b: '4', 0x4c: '5', 0x4d: '6', 0x4f: '1', 0x50: '2', 0x51: '3', 0x52: '0', 0x53: '.'}[scan]
	}
	if ascii >= 'a' && ascii <= 'z' {
		if (*flags&3 != 0) != (*flags&0x40 != 0) {
			ascii -= 'a' - 'A'
		}
	} else if *flags&3 != 0 && !extended {
		const plain = "1234567890-=[];'`,./\\"
		const shift = "!@#$%^&*()_+{}:\"~<>?|"
		for i := range plain {
			if ascii == plain[i] {
				ascii = shift[i]
				break
			}
		}
	}
	if *flags&4 != 0 {
		switch {
		case ascii >= 'a' && ascii <= 'z':
			ascii -= 'a' - 1
		case ascii >= 'A' && ascii <= 'Z':
			ascii -= 'A' - 1
		case ascii == '[':
			ascii = 27
		case ascii == '\\':
			ascii = 28
		case ascii == ']':
			ascii = 29
		case ascii == 13:
			ascii = 10
		}
	}
	if *flags&8 != 0 {
		ascii = 0
	}
	p.storeKeyboardWord(uint16(scan)<<8 | uint16(ascii))
}

func (p *pc) keyboardBIOS(r *x86state.Registers, flags *uint16) bool {
	p.beforeRAMWrite(0x400, 0x100)
	ah := byte(r.Rax >> 8)
	// The ROM's JNZ must return immediately for nonblocking calls even when
	// the caller's saved ZF is set.
	r.Rflags &^= 0x40
	switch ah {
	case 0, 1, 0x10, 0x11:
		head, tail := p.keyboardBounds()
		available := validKeyboardWord(head) && validKeyboardWord(tail) && head != tail
		if ah == 1 || ah == 0x11 {
			*flags &^= 0x40
			if !available {
				*flags |= 0x40
			}
		} else if !available {
			r.Rflags |= 0x40
			return true
		}
		if available {
			word := binary.LittleEndian.Uint16(p.ram[0x400+int(head):])
			if ah < 0x10 && byte(word) == 0xe0 {
				word &^= 0xff
			}
			setLow(&r.Rax, word)
			if ah == 0 || ah == 0x10 {
				binary.LittleEndian.PutUint16(p.ram[0x41a:], nextKeyboardWord(head))
			}
		}
	case 2:
		r.Rax = r.Rax&^0xff | uint64(p.ram[0x417])
	case 5:
		r.Rax &^= 0xff
		if !p.storeKeyboardWord(uint16(r.Rcx)) {
			r.Rax |= 1
		}
	case 0x12:
		setLow(&r.Rax, uint16(p.ram[0x417])|uint16(p.ram[0x418])<<8)
	default:
		return false
	}
	return true
}
