package cc

import (
	"encoding/binary"

	"j5.nz/cc/hypervisor"
)

// pciIDE exposes the ATA controller at 00:01.0. Both channels are
// fixed in compatibility mode (class 01/01, programming interface 80).
// BAR4 exposes the standard bus-master IDE registers. Native-mode channel
// BARs and a PCI interrupt pin are not advertised.
// The synthetic identity selects the guest's generic PCI IDE class driver.
type pciIDE struct {
	config        [256]byte
	reads, writes uint64 // Dwords touched, for bounded device inspection.
	bm            [16]byte
}

func newPCIIDE() *pciIDE {
	d := &pciIDE{}
	binary.LittleEndian.PutUint16(d.config[0:], 0x1234)
	binary.LittleEndian.PutUint16(d.config[2:], 0xcc01)
	d.config[4] = 1 // Firmware enables legacy I/O decoding.
	d.config[8], d.config[10], d.config[11] = 1, 1, 1
	d.config[9] = 0x80 // Bus-master IDE, fixed compatibility channels.
	binary.LittleEndian.PutUint32(d.config[0x20:], 0xc001)
	binary.LittleEndian.PutUint16(d.config[0x2c:], 0x1234)
	binary.LittleEndian.PutUint16(d.config[0x2e:], 0xcc01)
	d.config[0x3c] = 0xff // IRQ14/15 are compatibility-mode ISA interrupts.
	return d
}

func (d *pciIDE) write(offset int, value byte) {
	switch offset {
	case 4:
		d.config[offset] = value & 5 // I/O decoding and bus mastering.
	case 0x20:
		d.config[offset] = value&0xf0 | 1
	case 0x21, 0x22, 0x23:
		d.config[offset] = value
	case 0x3c:
		d.config[offset] = value
	}
}

func (p *pc) pciIO(ex hypervisor.X86Exit) error {
	oldCommand := byte(0)
	if p.pciIDE != nil {
		oldCommand = p.pciIDE.config[4]
	}
	for i := uint32(0); i < ex.Count; i++ {
		data := ex.Data[int(i)*int(ex.Size) : int(i+1)*int(ex.Size)]
		if ex.Port == 0xcf8 && ex.Size == 4 {
			if ex.Write {
				p.pciAddress = binary.LittleEndian.Uint32(data) & 0x80fffffc
			} else {
				binary.LittleEndian.PutUint32(data, p.pciAddress)
			}
			continue
		}
		for j := range data {
			port := int(ex.Port) + j
			value := byte(0xff)
			if port >= 0xcfc && port <= 0xcff && p.pciIDE != nil && p.pciAddress&0xffffff00 == 0x80000800 {
				offset := int(p.pciAddress&0xfc) + port - 0xcfc
				if ex.Write {
					p.pciIDE.writes |= 1 << (offset / 4)
					p.pciIDE.write(offset, data[j])
				} else {
					p.pciIDE.reads |= 1 << (offset / 4)
				}
				value = p.pciIDE.config[offset]
			}
			if !ex.Write {
				data[j] = value
			}
		}
	}
	if p.ide != nil && p.pciIDE != nil && oldCommand != p.pciIDE.config[4] {
		if err := p.ide.signal(p.ide.pending); err != nil {
			return err
		}
		return p.tryIDEDMA()
	}
	return nil
}

func (p *pc) ideIO(ex hypervisor.X86Exit) error {
	if p.pciIDE != nil && p.pciIDE.config[4]&1 == 0 {
		if !ex.Write {
			for i := range ex.Data {
				ex.Data[i] = 0xff
			}
		}
		return nil
	}
	if err := p.ide.io(ex); err != nil {
		return err
	}
	return p.tryIDEDMA()
}
