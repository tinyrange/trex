package cc

import "j5.nz/cc/hypervisor"

// Polled 16550-compatible COM1. No incoming data and no UART IRQ are advertised.
// Divisor-latch accesses and loopback are kept distinct from console output.
func (p *pc) serialIO(ex hypervisor.X86Exit) error {
	offset := int(ex.Port - 0x3f8)
	for i := uint32(0); i < ex.Count; i++ {
		data := ex.Data[int(i)*int(ex.Size) : int(i+1)*int(ex.Size)]
		if ex.Size != 1 {
			if !ex.Write {
				for j := range data {
					data[j] = 0xff
				}
			}
			continue
		}
		if ex.Write {
			if offset == 0 && p.serial[3]&0x80 == 0 && p.serial[4]&0x10 == 0 {
				p.console = append(p.console, data[0])
				if len(p.console) > 65536 {
					p.console = p.console[len(p.console)-65536:]
				}
			}
			p.serial[offset] = data[0]
		} else {
			switch offset {
			case 0:
				if p.serial[3]&0x80 != 0 || p.serial[4]&0x10 != 0 {
					data[0] = p.serial[0]
				} else {
					data[0] = 0
				}
			case 2:
				data[0] = 1 // no interrupt
			case 5:
				data[0] = 0x60
				if p.serial[4]&0x10 != 0 {
					data[0] |= 1
				}
			case 6:
				data[0] = 0xb0
			default:
				data[0] = p.serial[offset]
			}
		}
	}
	return nil
}
