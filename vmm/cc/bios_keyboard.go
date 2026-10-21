package cc

import (
	"encoding/binary"
	"j5.nz/cc/hypervisor/x86state"
)

const biosKeyboardPort = 0xf2

func (p *pc) installKeyboardFirmware() {
	// IRQ1 consumes the controller's translated scan byte, updates the BIOS
	// keyboard state, then acknowledges the PIC. All interrupted flags and
	// registers survive, unlike a software service's return flags.
	copy(p.ram[0xf2100:], []byte{0x50, 0xe4, 0x60, 0xe6, biosKeyboardPort, 0xb0, 0x20, 0xe6, 0x20, 0x58, 0xcf})
	binary.LittleEndian.PutUint16(p.ram[9*4:], 0x2100)
	// Blocking INT16 reads must allow the keyboard and timer IRQs to run.
	copy(p.ram[0xf1058:], []byte{0xfb, 0xe6, biosPort, 0xcf})
	binary.LittleEndian.PutUint16(p.ram[0x41a:], 0x1e)
	binary.LittleEndian.PutUint16(p.ram[0x41c:], 0x1e)
	binary.LittleEndian.PutUint16(p.ram[0x480:], 0x1e)
	binary.LittleEndian.PutUint16(p.ram[0x482:], 0x3e)
	p.ram[0x496] = 0x10 // enhanced keyboard installed
}

func (p *pc) biosKeyBounds() (uint16, uint16) {
	start, end := binary.LittleEndian.Uint16(p.ram[0x480:]), binary.LittleEndian.Uint16(p.ram[0x482:])
	if start < 0x1e || end > 0x100 || end <= start || (end-start)&1 != 0 {
		return 0x1e, 0x3e
	}
	return start, end
}
func (p *pc) biosKeyNext(pos uint16) uint16 {
	start, end := p.biosKeyBounds()
	pos += 2
	if pos >= end {
		pos = start
	}
	return pos
}
func (p *pc) biosKeyStore(key uint16) bool {
	head, tail := binary.LittleEndian.Uint16(p.ram[0x41a:]), binary.LittleEndian.Uint16(p.ram[0x41c:])
	start, end := p.biosKeyBounds()
	if head < start || head >= end || tail < start || tail >= end || (head-start)&1 != 0 || (tail-start)&1 != 0 {
		return false
	}
	next := p.biosKeyNext(tail)
	if next == head {
		return false
	}
	binary.LittleEndian.PutUint16(p.ram[0x400+int(tail):], key)
	binary.LittleEndian.PutUint16(p.ram[0x41c:], next)
	return true
}
func (p *pc) keyboardBIOS(r *x86state.Registers, flags *uint16) bool {
	ah := byte(r.Rax >> 8)
	switch ah {
	case 0, 1, 0x10, 0x11:
		head, tail := binary.LittleEndian.Uint16(p.ram[0x41a:]), binary.LittleEndian.Uint16(p.ram[0x41c:])
		start, end := p.biosKeyBounds()
		empty := head == tail || head < start || head >= end || (head-start)&1 != 0
		if ah == 1 || ah == 0x11 {
			*flags &^= 0x40
			if empty {
				*flags |= 0x40
				return false
			}
		} else if empty {
			return true
		}
		key := binary.LittleEndian.Uint16(p.ram[0x400+int(head):])
		if ah < 0x10 && byte(key) == 0xe0 {
			key &^= 255
		}
		setLow(&r.Rax, key)
		if ah == 0 || ah == 0x10 {
			binary.LittleEndian.PutUint16(p.ram[0x41a:], p.biosKeyNext(head))
		}
	case 2:
		r.Rax = r.Rax&^255 | uint64(p.ram[0x417])
	case 5:
		r.Rax &^= 255
		if !p.biosKeyStore(uint16(r.Rcx)) {
			r.Rax |= 1
		}
	case 0x12:
		setLow(&r.Rax, uint16(p.ram[0x417])|uint16(p.ram[0x418]&^0x0c|p.ram[0x496]&0x0c)<<8)
	default:
		p.observeUnsupportedBIOS(p.lastService)
	}
	return false
}

// Translated set-1 scan codes. The controller handles set-2 translation; this
// layer owns only the traditional BIOS ring and shift state used before an OS
// installs its own keyboard interrupt handler.
func (p *pc) biosKeyboardScan(scan byte) {
	p.beforeRAMWrite(0x400, 0x100)
	if scan == 0xe0 {
		p.biosKeyPrefix = 1
		return
	}
	if scan == 0xe1 {
		p.biosKeyPrefix = 0x85
		return
	}
	if p.biosKeyPrefix&0x80 != 0 {
		p.biosKeyPrefix--
		if p.biosKeyPrefix == 0x80 {
			p.biosKeyPrefix = 0
		}
		return
	}
	extended := p.biosKeyPrefix == 1
	p.biosKeyPrefix = 0
	release := scan&0x80 != 0
	scan &= 0x7f
	flags := &p.ram[0x417]
	var mask byte
	switch scan {
	case 0x2a:
		if !extended {
			mask = 2
		}
	case 0x36:
		if !extended {
			mask = 1
		}
	case 0x1d:
		mask = 4
	case 0x38:
		mask = 8
	}
	if mask != 0 {
		if release {
			*flags &^= mask
		} else {
			*flags |= mask
		}
		if mask == 4 || mask == 8 {
			location, bit := 0x418, mask>>2
			if extended {
				location, bit = 0x496, mask
			}
			if release {
				p.ram[location] &^= bit
			} else {
				p.ram[location] |= bit
			}
			// Either left or right Ctrl/Alt can keep the aggregate flag set.
			if p.ram[0x418]&(mask>>2) != 0 || p.ram[0x496]&mask != 0 {
				*flags |= mask
			}
		}
		return
	}
	if scan == 0x3a || scan == 0x45 || scan == 0x46 {
		bit := byte(0x40)
		if scan == 0x45 {
			bit = 0x20
		}
		if scan == 0x46 {
			bit = 0x10
		}
		if release {
			p.ram[0x418] &^= bit
		} else if p.ram[0x418]&bit == 0 {
			p.ram[0x418] |= bit
			*flags ^= bit
		}
		return
	}
	if release || scan == 0 || scan >= 0x59 {
		return
	}
	var ch byte
	if scan < 0x3a {
		normal := "\x00\x1b1234567890-=\b\tqwertyuiop[]\r\x00asdfghjkl;'`\x00\\zxcvbnm,./\x00*\x00 "
		shifted := "\x00\x1b!@#$%^&*()_+\b\tQWERTYUIOP{}\r\x00ASDFGHJKL:\"~\x00|ZXCVBNM<>?\x00*\x00 "
		if int(scan) < len(normal) {
			ch = normal[scan]
			shift := *flags&3 != 0
			if ch >= 'a' && ch <= 'z' && *flags&0x40 != 0 {
				shift = !shift
			}
			if shift {
				ch = shifted[scan]
			}
		}
	} else if scan >= 0x47 && scan <= 0x53 {
		if !extended && (*flags&0x20 != 0) != (*flags&3 != 0) {
			ch = "789-456+1230."[scan-0x47]
		}
		if scan == 0x4a {
			ch = '-'
		}
		if scan == 0x4e {
			ch = '+'
		}
	}
	if extended && scan == 0x35 {
		ch = '/'
	}
	if *flags&4 != 0 {
		if ch >= 'a' && ch <= 'z' {
			ch -= 0x60
		} else if ch >= 'A' && ch <= 'Z' {
			ch -= 0x40
		} else {
			switch ch {
			case '[':
				ch = 27
			case '\\':
				ch = 28
			case ']':
				ch = 29
			case '^':
				ch = 30
			case '_':
				ch = 31
			case '2', ' ':
				ch = 0
			case '6':
				ch = 30
			case '-':
				ch = 31
			case '\r':
				ch = 10
			default:
				ch = 0
			}
		}
	}
	if *flags&8 != 0 {
		ch = 0
	}
	if extended && ch == 0 {
		ch = 0xe0
	}
	p.biosKeyStore(uint16(scan)<<8 | uint16(ch))
}
