package cc

import (
	"encoding/binary"
	"fmt"

	"j5.nz/cc/hypervisor"
	"j5.nz/cc/hypervisor/x86state"
)

const videoRequestPort = 0xf4
const videoDataPort = 0xf5

type videoPacket struct {
	args          [6]uint16
	result        [7]uint16
	written, read int
}

// The ROM sends its register values through I/O instead of borrowing native
// CPU registers. Windows x64 interprets this same ROM and forwards I/O, so
// native and interpreted firmware calls have identical device semantics.
func (p *pc) installVideoFirmware() {
	binary.LittleEndian.PutUint16(p.ram[0x10*4:], 0x5000)
	for ch := 0; ch < 256; ch++ {
		copy(p.ram[0xf6000+ch*16:], biosTextFont[ch*32:ch*32+16])
	}
	copy(p.ram[0xf7000:], rasterBIOSFontHeight(14))
	copy(p.ram[0xf8000:], rasterBIOSFontHeight(8))
	binary.LittleEndian.PutUint32(p.ram[0x1f*4:], 0xf0008400)
	binary.LittleEndian.PutUint32(p.ram[0x43*4:], 0xf0006000)
	// Palette blocks must be read by the guest ROM, not through host CPU
	// registers: the Windows x64 video-ROM interpreter uses the same entry.
	copy(p.ram[0xf5000:], []byte{0x3d, 0x02, 0x10, 0x0f, 0x84, 0xf9, 0x00})
	copy(p.ram[0xf5100:], []byte{
		0x50, 0x53, 0x51, 0x52, 0x56, // save AX,BX,CX,DX,SI
		0x89, 0xd6, 0xba, 0xda, 0x03, 0xec, // SI=DX; reset attribute flip-flop
		0xba, 0xc0, 0x03, 0x31, 0xdb, 0xb9, 0x10, 0x00,
		0x88, 0xd8, 0xee, 0x26, 0x8a, 0x04, 0xee, 0x46, 0x43, 0xe2, 0xf5,
		0xb0, 0x11, 0xee, 0x26, 0x8a, 0x04, 0xee, // overscan (17th byte)
		0xb0, 0x20, 0xee, // restore attribute controller display enable
		0x5e, 0x5a, 0x59, 0x5b, 0x58, 0xcf,
	})
	copy(p.ram[0xf5007:], []byte{
		0x55, 0x89, 0xe5, 0x50, 0x53, 0x51, 0x52, 0x06, // save BP,AX,BX,CX,DX,ES
		0xba, 0xf4, 0, 0x31, 0xc0, 0xee, 0x42, // reset packet, select data port
		0x8b, 0x46, 0xfe, 0xef, 0x8b, 0x46, 0xfc, 0xef,
		0x8b, 0x46, 0xfa, 0xef, 0x8b, 0x46, 0xf8, 0xef,
		0x8b, 0x46, 0, 0xef, 0x8b, 0x46, 0xf6, 0xef, // original BP, ES
		0xed, 0x89, 0x46, 0xfe, 0xed, 0x89, 0x46, 0xfc,
		0xed, 0x89, 0x46, 0xfa, 0xed, 0x89, 0x46, 0xf8,
		0xed, 0x89, 0x46, 0, 0xed, 0x89, 0x46, 0xf6, // returned BP,ES
		0xed, 0x83, 0x66, 6, 0xfe, 0x09, 0x46, 6, // return CF in interrupt frame
		0x07, 0x5a, 0x59, 0x5b, 0x58, 0x5d, 0xcf,
	})
}

func (p *pc) videoIO(ex hypervisor.X86Exit) error {
	if ex.Port == videoRequestPort {
		if !ex.Write || ex.Size != 1 || ex.Count != 1 || ex.Data[0] != 0 {
			return fmt.Errorf("invalid video firmware packet reset")
		}
		p.videoPacket = videoPacket{}
		return nil
	}
	if ex.Size != 2 {
		return fmt.Errorf("video firmware packet requires word I/O")
	}
	packet := &p.videoPacket
	for i := uint32(0); i < ex.Count; i++ {
		data := ex.Data[i*2 : i*2+2]
		if ex.Write {
			if packet.written >= len(packet.args) {
				return fmt.Errorf("video firmware packet overflow")
			}
			packet.args[packet.written] = binary.LittleEndian.Uint16(data)
			packet.written++
			if packet.written == len(packet.args) {
				r := x86state.Registers{Rax: uint64(packet.args[0]), Rbx: uint64(packet.args[1]), Rcx: uint64(packet.args[2]), Rdx: uint64(packet.args[3]), Rbp: uint64(packet.args[4])}
				p.lastService = fmt.Sprintf("INT 10 AX=%04x", packet.args[0])
				es := packet.args[5]
				carry, err := p.videoBIOS(&r, &es)
				if err != nil {
					return err
				}
				packet.result = [7]uint16{uint16(r.Rax), uint16(r.Rbx), uint16(r.Rcx), uint16(r.Rdx), uint16(r.Rbp), es, 0}
				if carry {
					packet.result[6] = 1
				}
			}
		} else {
			if packet.written != len(packet.args) || packet.read >= len(packet.result) {
				return fmt.Errorf("incomplete video firmware packet read")
			}
			binary.LittleEndian.PutUint16(data, packet.result[packet.read])
			packet.read++
		}
	}
	return nil
}

func (p *pc) videoBIOS(r *x86state.Registers, segments ...*uint16) (bool, error) {
	var selector uint16
	es := &selector
	if len(segments) > 0 {
		es = segments[0]
	}
	p.beforeRAMWrite(0x400, 0x100)
	ah, al := byte(r.Rax>>8), byte(r.Rax)
	carry := false
	unsupported := func() {
		p.observeUnsupportedBIOS(fmt.Sprintf("INT 10 AX=%04x BX=%04x", uint16(r.Rax), uint16(r.Rbx)))
		carry = true
		setAH(&r.Rax, 0x86)
	}
	defer p.vga.syncText()
	switch ah {
	case 0:
		if err := p.vga.setMode(al); err != nil {
			return false, err
		}
		p.mode = al & 0x7f
		p.ram[0x449] = p.mode
		p.cursor = 0
	case 1:
	case 2:
		p.cursor = uint16(r.Rdx)
		binary.LittleEndian.PutUint16(p.ram[0x450:], p.cursor)
	case 3:
		setLow(&r.Rdx, p.cursor)
		setLow(&r.Rcx, 0x0607)
	case 5:
	case 6, 7:
		for i := 0xb8000; i < 0xb8000+4000; i += 2 {
			p.ram[i] = ' '
			p.ram[i+1] = byte(r.Rbx >> 8)
		}
	case 8:
		off := 0xb8000 + int(p.cursor>>8)*160 + int(p.cursor&255)*2
		if off+2 <= 0xb8000+4000 {
			setLow(&r.Rax, binary.LittleEndian.Uint16(p.ram[off:]))
		}
	case 9, 10:
		for i := 0; i < int(uint16(r.Rcx)); i++ {
			off := 0xb8000 + int(p.cursor>>8)*160 + (int(p.cursor&255)+i)*2
			if off+2 > 0xb8000+4000 {
				break
			}
			p.ram[off] = al
			if ah == 9 {
				p.ram[off+1] = byte(r.Rbx)
			}
		}
	case 0x0e:
		p.putchar(al)
	case 0x0f:
		setLow(&r.Rax, uint16(p.mode)|80<<8)
		r.Rbx &^= 0xff00
	case 0x10:
		switch al {
		case 0:
			if byte(r.Rbx) < 16 {
				p.vga.attr[byte(r.Rbx)] = byte(r.Rbx>>8) & 63
			}
		case 1:
			p.vga.attr[0x11] = byte(r.Rbx>>8) & 63
		case 2, 9:
			s, err := p.cpu.SystemRegisters()
			if err != nil {
				return false, err
			}
			b, err := p.biosReadContext(s.Es.Base+uint64(uint16(r.Rdx)), 17, s)
			if err != nil {
				return false, err
			}
			if al == 2 {
				for i := 0; i < 16; i++ {
					p.vga.attr[i] = b[i] & 63
				}
				p.vga.attr[0x11] = b[16] & 63
			} else {
				copy(b[:16], p.vga.attr[:16])
				b[16] = p.vga.attr[0x11]
				if err := p.biosCopy(s.Es.Base+uint64(uint16(r.Rdx)), b, true, s); err != nil {
					return false, err
				}
			}
		case 3:
			p.vga.attr[0x10] &^= 8
			if byte(r.Rbx)&1 != 0 {
				p.vga.attr[0x10] |= 8
			}
		case 0x10, 0x15:
			index := uint16(r.Rbx)
			if index >= 256 {
				unsupported()
				break
			}
			if al == 0x10 {
				p.vga.dac[index] = [3]byte{byte(r.Rdx>>8) & 63, byte(r.Rcx>>8) & 63, byte(r.Rcx) & 63}
			} else {
				c := p.vga.dac[index]
				setAH(&r.Rdx, c[0])
				setLow(&r.Rcx, uint16(c[1])<<8|uint16(c[2]))
			}
		case 0x12, 0x17:
			// VGA DAC blocks are RGB triples, not attribute-controller
			// entries. Windows programs its UI grays through this service.
			first, count := uint64(uint16(r.Rbx)), uint64(uint16(r.Rcx))
			if first >= 256 || count > 256-first {
				unsupported()
				break
			}
			s, err := p.biosAccessSystem()
			if err != nil {
				return false, err
			}
			address := s.Es.Base + uint64(uint16(r.Rdx))
			if al == 0x12 {
				data, err := p.biosReadContext(address, count*3, s)
				if err != nil {
					return false, err
				}
				for i := uint64(0); i < count; i++ {
					p.vga.dac[first+i] = [3]byte{data[i*3] & 63, data[i*3+1] & 63, data[i*3+2] & 63}
				}
			} else {
				data := make([]byte, count*3)
				for i := uint64(0); i < count; i++ {
					copy(data[i*3:], p.vga.dac[first+i][:])
				}
				if err := p.biosCopy(address, data, true, s); err != nil {
					return false, err
				}
			}
		case 7:
			if byte(r.Rbx) < 16 {
				setAH(&r.Rbx, p.vga.attr[byte(r.Rbx)])
			}
		case 8:
			setAH(&r.Rbx, p.vga.attr[0x11])
		default:
			unsupported()
		}
	case 0x11:
		if al != 0x30 {
			unsupported()
			break
		}
		var address uint32
		switch byte(r.Rbx >> 8) {
		case 0:
			address = binary.LittleEndian.Uint32(p.ram[0x1f*4:])
		case 1:
			address = binary.LittleEndian.Uint32(p.ram[0x43*4:])
		case 2, 5:
			address = 0xf0007000
		case 3:
			address = 0xf0008000
		case 4:
			address = 0xf0008400
		case 6, 7:
			address = 0xf0006000
		default:
			unsupported()
			break
		}
		if address != 0 {
			*es = uint16(address >> 16)
			setLow(&r.Rbp, uint16(address))
			setLow(&r.Rcx, uint16(p.ram[0x485]))
			r.Rdx = r.Rdx&^255 | uint64(p.ram[0x484])
		}
	case 0x12:
		if byte(r.Rbx) == 0x30 && al <= 2 {
			r.Rax = r.Rax&^255 | 0x12
			break
		}
		if byte(r.Rbx) == 0x10 {
			setLow(&r.Rbx, 3)
			setLow(&r.Rcx, 0)
		} else {
			unsupported()
		}
	case 0x1a:
		setLow(&r.Rax, 0x1a)
		setLow(&r.Rbx, 8)
	default:
		unsupported()
	}
	return carry, nil
}
