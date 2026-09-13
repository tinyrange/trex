package cc

import (
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/tinyrange/trex/vmm"
	"j5.nz/cc/hypervisor"
	"j5.nz/cc/hypervisor/x86state"
)

const biosPort = 0xf1

// pc implements firmware against guest memory and a portable block device.
// Each IVT entry points to an OUT/IRET trampoline; native execution retains
// all mode switches and executes the original boot sector and loader.
type pc struct {
	nic           *ne2000
	framebuffer   []byte
	channelMemory []byte
	channelName   string
	cpu           hypervisor.X86
	ram           []byte
	disk          vmm.Disk
	geometry      vmm.CHSGeometry
	biosGeometry  vmm.CHSGeometry
	now           func() time.Time
	started       time.Time
	console       []byte
	cursor        uint16
	mode          byte
	ports         map[uint16]byte
	cmos          [128]byte
	cmosIndex     byte
	lastService   string
	rtcNext       time.Time
	rtcIRQ        bool
	ide           *ide
	vga           *vga
	inputTrace    []string
	keyboard      *keyboard
	rtcTrace      []any
}

func newPC(cpu hypervisor.X86, ram []byte, disk vmm.Disk, now func() time.Time) (*pc, error) {
	p := &pc{cpu: cpu, ram: ram, disk: disk, now: now, started: now(), mode: 3, ports: make(map[uint16]byte)}
	p.cmos[0x0a], p.cmos[0x0b] = 0x26, 2
	p.geometry = vmm.CHSGeometry{Cylinders: int(disk.Device.Geometry().Size / 512 / 16 / 63), Heads: 16, Sectors: 63}
	if disk.CHS != nil {
		p.geometry = *disk.CHS
	}
	if p.geometry.Cylinders > 16383 {
		p.geometry.Cylinders = 16383
	}
	p.ide = newIDE(disk, p.geometry, cpu.SetIRQ)
	p.biosGeometry = p.geometry
	if disk.CHS == nil {
		p.biosGeometry = translatedGeometry(uint64(disk.Device.Geometry().Size / 512))
	}
	p.vga = newVGA(ram[0xb8000:0xc0000])
	p.keyboard = newKeyboard(cpu.SetIRQ)
	p.initializeCMOS()
	for i := 0; i < 256; i++ {
		binary.LittleEndian.PutUint16(ram[i*4:], uint16(0x1000+i*4))
		binary.LittleEndian.PutUint16(ram[i*4+2:], 0xf000)
		copy(ram[0xf1000+i*4:], []byte{0xe6, biosPort, 0xcf, 0x90})
	}
	// IRQ0 advances the BDA tick count and acknowledges the master PIC.
	copy(ram[0xf2000:], []byte{0x50, 0x1e, 0xb8, 0x40, 0, 0x8e, 0xd8, 0x66, 0xff, 0x06, 0x6c, 0, 0xcd, 0x1c, 0xb0, 0x20, 0xe6, 0x20, 0x1f, 0x58, 0xcf})
	binary.LittleEndian.PutUint16(ram[8*4:], 0x2000)
	ram[0xf1000+0x1c*4] = 0xcf // default user timer hook
	// POST programs the real interrupt controllers and timer before entering
	// the original MBR. These instructions execute against KVM's PC devices.
	post := []byte{0xfa}
	for _, io := range [][2]byte{{0x20, 0x11}, {0xa0, 0x11}, {0x21, 8}, {0xa1, 0x70}, {0x21, 4}, {0xa1, 2}, {0x21, 1}, {0xa1, 1}, {0x21, 0xfe}, {0xa1, 0xff}, {0x43, 0x36}, {0x40, 0}, {0x40, 0}} {
		post = append(post, 0xb0, io[1], 0xe6, io[0])
	}
	post = append(post, 0x31, 0xc0, 0xfb, 0xea, 0, 0x7c, 0, 0)
	copy(ram[0xf4000:], post)
	binary.LittleEndian.PutUint16(ram[0x410:], 0x0026) // VGA, no floppy, PS/2 pointing device
	binary.LittleEndian.PutUint16(ram[0x413:], 640)
	binary.LittleEndian.PutUint16(ram[0x44a:], 80)
	binary.LittleEndian.PutUint16(ram[0x44c:], 0x1000)
	binary.LittleEndian.PutUint16(ram[0x463:], 0x3d4)
	ram[0x449] = 3
	ram[0x484] = 24
	ram[0x485] = 16
	ram[0x475] = 1
	copy(ram[0xffff5:], []byte("09/13/26"))
	ram[0xffffe] = 0xfc
	// AT system configuration table and fixed disk parameter table.
	copy(ram[0xf3000:], []byte{8, 0, 0xfc, 0, 1, 0x70, 0, 0, 0, 0})
	binary.LittleEndian.PutUint16(ram[0x104:], 0x3100)
	binary.LittleEndian.PutUint16(ram[0x106:], 0xf000)
	binary.LittleEndian.PutUint16(ram[0xf3100:], uint16(p.geometry.Cylinders))
	ram[0xf3102] = byte(p.geometry.Heads)
	ram[0xf310e] = byte(p.geometry.Sectors)
	for i := 0xb8000; i < 0xb8000+4000; i += 2 {
		ram[i] = ' '
		ram[i+1] = 7
	}
	p.vga.syncText()
	if n, err := disk.Device.ReadAt(ram[0x7c00:0x7e00], 0); err != nil || n != 512 {
		return nil, fmt.Errorf("read boot sector: %w", err)
	}
	if binary.LittleEndian.Uint16(ram[0x7dfe:]) != 0xaa55 {
		return nil, fmt.Errorf("disk has no boot signature")
	}
	s, err := cpu.SystemRegisters()
	if err != nil {
		return nil, err
	}
	seg := x86state.Segment{Limit: 0xffff, Present: 1, S: 1, Type: 3}
	s.Cs, s.Ds, s.Es, s.Ss, s.Fs, s.Gs = seg, seg, seg, seg, seg, seg
	s.Cs.Type = 11
	s.Cs.Base, s.Cs.Selector = 0xf0000, 0xf000
	s.Cr0 = 0x10
	s.Cr2 = 0
	s.Cr3 = 0
	s.Cr4 = 0
	s.Efer = 0
	s.Idt = x86state.DescriptorTable{Limit: 0x3ff}
	if err = cpu.SetSystemRegisters(s); err != nil {
		return nil, err
	}
	err = cpu.SetRegisters(x86state.Registers{Rip: 0x4000, Rsp: 0x7c00, Rdx: 0x80, Rflags: 2})
	return p, err
}

func (p *pc) initializeCMOS() {
	p.cmos[0x12] = 0xf0
	p.cmos[0x19] = 47
	p.cmos[0x15] = 0x80
	p.cmos[0x16] = 2
	extended := uint16(min((len(p.ram)-(1<<20))/1024, 65535))
	binary.LittleEndian.PutUint16(p.cmos[0x17:], extended)
	binary.LittleEndian.PutUint16(p.cmos[0x30:], extended)
	binary.LittleEndian.PutUint16(p.cmos[0x1b:], uint16(p.geometry.Cylinders))
	p.cmos[0x1d] = byte(p.geometry.Heads)
	p.cmos[0x23] = byte(p.geometry.Sectors)
	// The AT CMOS checksum covers 10h..2Dh inclusive and is big-endian.
	// NT 3.1 HAL uses its validity to select the AT century byte at 32h;
	// an invalid checksum makes it probe the alternate byte at 37h.
	var sum uint16
	for _, v := range p.cmos[0x10:0x2e] {
		sum += uint16(v)
	}
	binary.BigEndian.PutUint16(p.cmos[0x2e:], sum)
}

func (p *pc) memory(addr, size uint64) ([]byte, error) {
	if addr > uint64(len(p.ram)) || size > uint64(len(p.ram))-addr {
		return nil, fmt.Errorf("guest memory out of range: %#x+%#x", addr, size)
	}
	return p.ram[addr : addr+size], nil
}

func (p *pc) physical(address uint64, s x86state.SystemRegisters) (uint64, error) {
	if s.Cr0&(1<<31) == 0 {
		return address, nil
	}
	if s.Cr4&(1<<5) != 0 {
		return 0, fmt.Errorf("PAE address translation is not implemented")
	}
	dir, err := p.memory((s.Cr3&0xfffff000)+(address>>22&1023)*4, 4)
	if err != nil {
		return 0, err
	}
	pde := uint64(binary.LittleEndian.Uint32(dir))
	if pde&1 == 0 {
		return 0, fmt.Errorf("unmapped PDE for %#x", address)
	}
	if pde&128 != 0 && s.Cr4&16 != 0 {
		return pde&0xffc00000 | address&0x3fffff, nil
	}
	table, err := p.memory((pde&0xfffff000)+(address>>12&1023)*4, 4)
	if err != nil {
		return 0, err
	}
	pte := uint64(binary.LittleEndian.Uint32(table))
	if pte&1 == 0 {
		return 0, fmt.Errorf("unmapped PTE for %#x", address)
	}
	return pte&0xfffff000 | address&4095, nil
}
func setLow(r *uint64, v uint16) { *r = (*r &^ 0xffff) | uint64(v) }
func setAH(r *uint64, v byte)    { *r = (*r &^ 0xff00) | uint64(v)<<8 }

func (p *pc) bios() error {
	if err := p.cpu.CompleteIO(); err != nil {
		return err
	}
	r, err := p.cpu.Registers()
	if err != nil {
		return err
	}
	s, err := p.cpu.SystemRegisters()
	if err != nil {
		return err
	}
	addr := s.Cs.Base + r.Rip
	if addr < 0xf1000 || addr >= 0xf1400 || (addr-0xf1000)%4 != 2 {
		return fmt.Errorf("BIOS trap outside firmware: %#x", addr)
	}
	vector := (addr - 0xf1000) / 4
	ah, al := byte(r.Rax>>8), byte(r.Rax)
	p.lastService = fmt.Sprintf("INT %02x AX=%04x", vector, uint16(r.Rax))
	flags, err := p.memory(s.Ss.Base+uint64(uint16(r.Rsp+4)), 2)
	if err != nil {
		return err
	}
	f := binary.LittleEndian.Uint16(flags)
	carry := false
	unsupported := func() { carry = true; setAH(&r.Rax, 0x86) }
	switch vector {
	case 0x10:
		defer p.vga.syncText()
		switch ah {
		case 0:
			if err := p.vga.setMode(al); err != nil {
				return err
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
	case 0x11:
		setLow(&r.Rax, binary.LittleEndian.Uint16(p.ram[0x410:]))
	case 0x12:
		setLow(&r.Rax, 640)
	case 0x13:
		if byte(r.Rdx) != 0x80 {
			carry = true
			setAH(&r.Rax, 1)
			break
		}
		switch ah {
		case 0, 1, 0x0c, 0x10:
			setAH(&r.Rax, 0)
		case 2, 3:
			g := p.biosGeometry
			c := int(byte(r.Rcx>>8)) | int(byte(r.Rcx)&0xc0)<<2
			h := int(byte(r.Rdx >> 8))
			sec := int(byte(r.Rcx) & 63)
			count := int(al)
			lba := (c*g.Heads+h)*g.Sectors + sec - 1
			if count == 0 || c >= g.Cylinders || h >= g.Heads || sec < 1 || sec > g.Sectors {
				carry = true
				setAH(&r.Rax, 4)
				break
			}
			buf, e := p.memory(s.Es.Base+uint64(uint16(r.Rbx)), uint64(count*512))
			if e != nil {
				return e
			}
			if ah == 3 {
				w, ok := p.disk.Device.(io.WriterAt)
				if !ok || p.disk.ReadOnly {
					e = fmt.Errorf("read-only disk")
				} else {
					_, e = w.WriteAt(buf, int64(lba)*512)
				}
			} else {
				_, e = p.disk.Device.ReadAt(buf, int64(lba)*512)
			}
			if e != nil {
				carry = true
				setAH(&r.Rax, 4)
			} else {
				setAH(&r.Rax, 0)
			}
		case 8:
			c := p.biosGeometry.Cylinders - 1
			setLow(&r.Rcx, uint16((c&255)<<8|(c>>8)<<6|p.biosGeometry.Sectors))
			setLow(&r.Rdx, uint16((p.biosGeometry.Heads-1)<<8|1))
			setAH(&r.Rax, 0)
		case 0x15:
			setAH(&r.Rax, 3)
			count := uint32(p.disk.Device.Geometry().Size / 512)
			setLow(&r.Rcx, uint16(count>>16))
			setLow(&r.Rdx, uint16(count))
		case 0x41:
			if uint16(r.Rbx) != 0x55aa {
				carry = true
				setAH(&r.Rax, 1)
				break
			}
			setLow(&r.Rbx, 0xaa55)
			setLow(&r.Rcx, 1) // Fixed-disk access subset; no removable media.
			setAH(&r.Rax, 0x21)
		case 0x42, 0x43:
			status := p.extendedDiskTransfer(s.Ds.Base+uint64(uint16(r.Rsi)), ah == 0x43, al)
			carry = status != 0
			setAH(&r.Rax, status)
		case 0x44, 0x47:
			status := p.extendedDiskPosition(s.Ds.Base+uint64(uint16(r.Rsi)), ah == 0x44)
			carry = status != 0
			setAH(&r.Rax, status)
		case 0x48:
			status := p.extendedDiskParameters(s.Ds.Base + uint64(uint16(r.Rsi)))
			carry = status != 0
			setAH(&r.Rax, status)
		default:
			carry = true
			setAH(&r.Rax, 1)
		}
	case 0x15:
		switch ah {
		case 0xc2:
			// NTDETECT uses the BIOS pointing-device reset/ID services before
			// the protected-mode i8042 driver takes over the auxiliary port.
			switch al {
			case 1, 5:
				if al == 5 && byte(r.Rbx>>8) != 3 {
					carry = true
					setAH(&r.Rax, 2)
					break
				}
				p.keyboard.mouseEnabled = false
				p.keyboard.mouseRemote = false
				p.keyboard.mouseScaling = false
				p.keyboard.mouseRate = 100
				p.keyboard.mouseResolution = 2
				setLow(&r.Rbx, 0x00aa)
				setAH(&r.Rax, 0)
			case 4:
				r.Rbx &^= 0xff00
				setAH(&r.Rax, 0)
			default:
				unsupported()
			}
		case 0x88:
			setLow(&r.Rax, uint16(min((len(p.ram)-(1<<20))/1024, 0xfc00)))
		case 0xc0:
			s.Es.Base = 0xf0000
			s.Es.Selector = 0xf000
			setLow(&r.Rbx, 0x3000)
			setAH(&r.Rax, 0)
		case 0xc1:
			unsupported()
		case 0x24:
			setAH(&r.Rax, 0)
		case 0x86, 0x90, 0x91:
			setAH(&r.Rax, 0)
		default:
			unsupported()
		}
	case 0x16:
		switch ah {
		case 1, 0x11:
			f |= 0x40
		case 2:
			setLow(&r.Rax, 0)
		case 0, 0x10:
			return fmt.Errorf("BIOS awaiting keyboard input")
		default:
			unsupported()
		}
	case 0x1a:
		t := p.now().UTC()
		bcd := func(v int) uint16 { return uint16(v/10*16 + v%10) }
		switch ah {
		case 0:
			ticks := uint32(p.now().Sub(p.started).Seconds() * 18.2065)
			setLow(&r.Rcx, uint16(ticks>>16))
			setLow(&r.Rdx, uint16(ticks))
			r.Rax &^= 255
		case 2:
			setLow(&r.Rcx, bcd(t.Hour())<<8|bcd(t.Minute()))
			setLow(&r.Rdx, bcd(t.Second())<<8)
		case 4:
			setLow(&r.Rcx, bcd(t.Year()/100)<<8|bcd(t.Year()%100))
			setLow(&r.Rdx, bcd(int(t.Month()))<<8|bcd(t.Day()))
		default:
			unsupported()
		}
	default:
		return fmt.Errorf("unhandled %s", p.lastService)
	}
	f &^= 1
	if carry {
		f |= 1
	}
	binary.LittleEndian.PutUint16(flags, f)
	if err = p.cpu.SetSystemRegisters(s); err != nil {
		return err
	}
	return p.cpu.SetRegisters(r)
}

func (p *pc) putchar(c byte) {
	if len(p.console) < 65536 {
		p.console = append(p.console, c)
	}
	row, col := int(p.cursor>>8), int(p.cursor&255)
	switch c {
	case '\r':
		col = 0
	case '\n':
		row++
	case '\b':
		if col > 0 {
			col--
		}
	default:
		if row < 25 && col < 80 {
			p.ram[0xb8000+row*160+col*2] = c
		}
		col++
		if col == 80 {
			col = 0
			row++
		}
	}
	if row >= 25 {
		copy(p.ram[0xb8000:0xb8000+3840], p.ram[0xb8000+160:0xb8000+4000])
		for i := 0xb8000 + 3840; i < 0xb8000+4000; i += 2 {
			p.ram[i] = ' '
			p.ram[i+1] = 7
		}
		row = 24
	}
	p.cursor = uint16(row<<8 | col)
	binary.LittleEndian.PutUint16(p.ram[0x450:], p.cursor)
}
