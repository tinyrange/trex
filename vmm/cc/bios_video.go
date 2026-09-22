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
	args          [4]uint16
	result        [5]uint16
	written, read int
}

// The ROM sends its register values through I/O instead of borrowing native
// CPU registers. Windows x64 interprets this same ROM and forwards I/O, so
// native and interpreted firmware calls have identical device semantics.
func (p *pc) installVideoFirmware() {
	binary.LittleEndian.PutUint16(p.ram[0x10*4:], 0x5000)
	copy(p.ram[0xf5000:], []byte{
		0x55, 0x89, 0xe5, 0x50, 0x53, 0x51, 0x52, // save BP,AX,BX,CX,DX
		0xba, 0xf4, 0, 0x31, 0xc0, 0xee, 0x42, // reset packet, select data port
		0x8b, 0x46, 0xfe, 0xef, 0x8b, 0x46, 0xfc, 0xef,
		0x8b, 0x46, 0xfa, 0xef, 0x8b, 0x46, 0xf8, 0xef,
		0xed, 0x89, 0x46, 0xfe, 0xed, 0x89, 0x46, 0xfc,
		0xed, 0x89, 0x46, 0xfa, 0xed, 0x89, 0x46, 0xf8,
		0xed, 0x83, 0x66, 6, 0xfe, 0x09, 0x46, 6, // return CF in interrupt frame
		0x5a, 0x59, 0x5b, 0x58, 0x5d, 0xcf,
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
				r := x86state.Registers{Rax: uint64(packet.args[0]), Rbx: uint64(packet.args[1]), Rcx: uint64(packet.args[2]), Rdx: uint64(packet.args[3])}
				p.lastService = fmt.Sprintf("INT 10 AX=%04x", packet.args[0])
				carry, err := p.videoBIOS(&r)
				if err != nil {
					return err
				}
				packet.result = [5]uint16{uint16(r.Rax), uint16(r.Rbx), uint16(r.Rcx), uint16(r.Rdx), 0}
				if carry {
					packet.result[4] = 1
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

func (p *pc) videoBIOS(r *x86state.Registers) (bool, error) {
	ah, al := byte(r.Rax>>8), byte(r.Rax)
	carry := false
	unsupported := func() { carry = true; setAH(&r.Rax, 0x86) }
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
	case 0x12:
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
