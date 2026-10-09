package cc

import (
	"encoding/binary"
	"fmt"
	"github.com/tinyrange/trex/emulator/cpu"

	"j5.nz/cc/hypervisor"
)

// pciIDE exposes the ATA controller at 00:01.0. Both channels are
// fixed in compatibility mode (class 01/01, programming interface 80).
// BAR4 exposes the standard bus-master IDE registers. Native-mode channel
// BARs and a PCI interrupt pin are not advertised.
// The synthetic identity selects the guest's generic PCI IDE class driver.
type pciIDE struct {
	ich7          bool
	config        [256]byte
	reads, writes uint64 // Dwords touched, for bounded device inspection.
	trace         []any  // Last 32 configuration transfers, including stopped guest PC.
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
	if d.ich7 && d.writeICH7(offset, value) {
		return
	}
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
	oldConfig := [256]byte{}
	if p.pciIDE != nil {
		oldConfig = p.pciIDE.config
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
			if port >= 0xcfc && port <= 0xcff && p.pciDisplay != nil && p.pciAddress&0xffffff00 == 0x80001000 {
				offset := int(p.pciAddress&0xfc) + port - 0xcfc
				if ex.Write {
					p.pciDisplay.write(offset, data[j])
				}
				value = p.pciDisplay.config[offset]
			}
			if port >= 0xcfc && port <= 0xcff && p.uhci != nil && p.pciAddress&0xffffff00 == 0x80001800 {
				offset := int(p.pciAddress&0xfc) + port - 0xcfc
				if ex.Write {
					p.uhci.writeConfig(offset, data[j])
				}
				value = p.uhci.config[offset]
			}
			if !ex.Write {
				data[j] = value
			}
		}
	}
	if p.pciIDE != nil && ex.Port >= 0xcfc && ex.Port <= 0xcff && p.pciAddress&0xffffff00 == 0x80000800 {
		row := map[string]any{"offset": int64(p.pciAddress&0xfc) + int64(ex.Port-0xcfc), "write": ex.Write, "data": fmt.Sprintf("%x", ex.Data)}
		if p.cpu != nil && p.darwin != nil {
			r, err := p.cpu.Registers()
			if err != nil {
				return err
			}
			row["pc"] = int64(r.Rip)
			row["sp"] = int64(r.Rsp)
			row["bp"] = int64(r.Rbp)
			if p.darwin != nil {
				s, err := p.cpu.SystemRegisters()
				if err != nil {
					return err
				}
				mem := efiMemory{p: p, system: &s}
				frames := []any{}
				bp := r.Rbp
				for n := 0; n < 6 && bp != 0; n++ {
					var frame [16]byte
					if err := mem.ReadMemory(bp, frame[:], cpu.Read); err != nil {
						break
					}
					ret := binary.LittleEndian.Uint64(frame[8:])
					frames = append(frames, map[string]any{"bp": int64(bp), "return": int64(ret)})
					next := binary.LittleEndian.Uint64(frame[:])
					if next <= bp {
						break
					}
					bp = next
				}
				row["frames"] = frames
			}
		}
		if len(p.pciIDE.trace) == 32 {
			copy(p.pciIDE.trace, p.pciIDE.trace[1:])
			p.pciIDE.trace = p.pciIDE.trace[:31]
		}
		p.pciIDE.trace = append(p.pciIDE.trace, row)
	}
	if p.ide != nil && p.pciIDE != nil && oldConfig != p.pciIDE.config {
		old := *p.pciIDE
		old.config = oldConfig
		if old.primaryIRQ() != p.pciIDE.primaryIRQ() && p.cpu != nil {
			if err := p.cpu.SetIRQ(old.primaryIRQ(), false); err != nil {
				return err
			}
		}
		if err := p.ide.signal(p.ide.pending); err != nil {
			return err
		}
		return p.tryIDEDMA()
	}
	return nil
}

func (p *pc) ideIO(ex hypervisor.X86Exit) error {
	// No second storage operation or task-file/reset mutation may race the
	// read worker. Reading status does not wait for disk completion.
	if ex.Write {
		if err := p.completeIDEDMARead(true); err != nil {
			return err
		}
	}
	if p.pciIDE != nil && !p.pciIDE.primaryEnabled() {
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
