package cc

import (
	"encoding/binary"
	"j5.nz/cc/hypervisor"
)

// ICH7 PATA register semantics are derived from Intel 307013, chapter 15.
// The board supplies one disk on the primary channel. The ICH7 secondary
// channel is unimplemented hardware: enabled reads return zero, not a disk.
// Electrical cable timing is recorded, not simulated; transfers use the same
// bounded native PIO/PRD block engine as the synthetic controller.
func newICH7PATA() *pciIDE {
	d := newPCIIDE()
	d.ich7 = true
	binary.LittleEndian.PutUint16(d.config[0:], 0x8086)
	binary.LittleEndian.PutUint16(d.config[2:], 0x27df)
	binary.LittleEndian.PutUint16(d.config[6:], 0x280)
	d.config[9] = 0x8a
	for n, v := range []uint32{0xd001, 0xd009, 0xd011, 0xd019} {
		binary.LittleEndian.PutUint32(d.config[0x10+n*4:], v)
	}
	d.config[0x3c], d.config[0x3d] = 16, 1
	d.config[0x41] = 0x80 // Firmware enables primary decode only.
	return d
}

func (d *pciIDE) writeICH7(offset int, value byte) bool {
	switch {
	case offset == 5:
		d.config[5] = value & 4 // Interrupt disable.
	case offset == 9:
		d.config[9] = 0x8a | value&5
	case offset >= 0x10 && offset <= 0x23:
		lane := (offset - 0x10) % 4
		if lane == 0 {
			mask := byte(0xf8)
			if offset == 0x14 || offset == 0x1c {
				mask = 0xfc
			}
			if offset == 0x20 {
				mask = 0xf0
			}
			d.config[offset] = value&mask | 1
		} else if lane == 1 {
			d.config[offset] = value
		}
		// The upper 16 address bits are reserved.
	case offset >= 0x40 && offset <= 0x44:
		mask := byte(0xff)
		if offset == 0x41 {
			mask = 0xf3
		}
		if offset == 0x43 {
			mask = 0xf7
		}
		d.config[offset] = value & mask
	case offset == 0x48:
		d.config[offset] = value & 0xf
	case offset == 0x4a || offset == 0x4b:
		d.config[offset] = value & 0x33
	case offset >= 0x54 && offset <= 0x57:
		masks := [4]byte{0xff, 0xf0, 0xff, 0}
		d.config[offset] = value & masks[offset-0x54]
	default:
		return false
	}
	return true
}

func (d *pciIDE) primaryEnabled() bool {
	return d.config[4]&1 != 0 && (!d.ich7 || d.config[0x41]&0x80 != 0 && d.config[0x56]&3 == 0)
}
func (d *pciIDE) commandBase(channel int) uint16 {
	if d.ich7 && d.config[9]&(1<<uint(channel*2)) != 0 {
		return binary.LittleEndian.Uint16(d.config[0x10+channel*8:]) & 0xfff8
	}
	if channel == 0 {
		return 0x1f0
	}
	return 0x170
}
func (d *pciIDE) controlPort(channel int) uint16 {
	if d.ich7 && d.config[9]&(1<<uint(channel*2)) != 0 {
		return (binary.LittleEndian.Uint16(d.config[0x14+channel*8:]) & 0xfffc) + 2
	}
	if channel == 0 {
		return 0x3f6
	}
	return 0x376
}
func (p *pc) ideDataPort() uint16 {
	if p.pciIDE != nil {
		return p.pciIDE.commandBase(0)
	}
	return 0x1f0
}

// Translate native PCI BARs into the shared ATA task-file implementation.
func (p *pc) routeIDE(ex hypervisor.X86Exit) (bool, error) {
	cmd, ctrl := uint16(0x1f0), uint16(0x3f6)
	if d := p.pciIDE; d != nil {
		cmd, ctrl = d.commandBase(0), d.controlPort(0)
		if d.ich7 {
			scmd, sctrl := d.commandBase(1), d.controlPort(1)
			if scmd != 0 && (ex.Port >= scmd && uint32(ex.Port) < uint32(scmd)+8 || ex.Port == sctrl) {
				if !ex.Write {
					v := byte(0xff)
					if d.config[4]&1 != 0 && d.config[0x43]&0x80 != 0 {
						v = 0
					}
					for n := range ex.Data {
						ex.Data[n] = v
					}
				}
				return true, nil
			}
		}
	}
	if cmd != 0 && ex.Port >= cmd && uint32(ex.Port) < uint32(cmd)+8 {
		ex.Port = 0x1f0 + (ex.Port - cmd)
		return true, p.ideIO(ex)
	}
	if cmd != 0 && ex.Port == ctrl {
		ex.Port = 0x3f6
		return true, p.ideIO(ex)
	}
	return false, nil
}

// Compatibility interrupts are hardwired to IRQ14. Native INTA has its own
// PCI route (GSI16); never alias the two in firmware or the controller.
func (d *pciIDE) primaryIRQ() uint32 {
	if d.ich7 && d.config[9]&1 != 0 {
		return 16
	}
	return 14
}
func (p *pc) setIDEIRQ(_ uint32, level bool) error {
	d := p.pciIDE
	if level {
		d.bm[2] |= 4
	}
	return p.cpu.SetIRQ(d.primaryIRQ(), level && d.primaryEnabled() && (d.primaryIRQ() == 14 || d.config[5]&4 == 0))
}
