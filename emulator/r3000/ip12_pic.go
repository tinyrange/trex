package r3000

const (
	ip12PICBase   = 0x1fa00000
	ip12BankUnit  = 4 << 20
	ip12EmptyBank = 0x3f
)

type ip12PIC struct {
	control uint32
	config  [2]uint32
	banks   [4][]byte
}

func (p *ip12PIC) reset(ram []byte, configured bool) {
	p.control = 2 // Big-endian data bus.
	p.config = [2]uint32{0x003f003f, 0x003f003f}
	var base uint32
	for i := range p.banks {
		n := 8 << 20
		switch {
		case len(ram) >= 32<<20:
			n = 32 << 20
		case len(ram) >= 16<<20:
			n = 16 << 20
		case len(ram) == 0:
			p.banks[i] = nil
			continue
		}
		p.banks[i], ram = ram[:n], ram[n:]
		if configured {
			shift := uint((1 - i%2) * 16)
			bank := uint32(n/ip12BankUnit-1)<<8 | base/ip12BankUnit
			p.config[i/2] = p.config[i/2]&^(0xffff<<shift) | bank<<shift
		}
		base += uint32(n)
	}
}

func (p *ip12PIC) memory(address, size uint32) []byte {
	if address >= 0x10000000 {
		return nil
	}
	for i, bank := range p.banks {
		cfg := p.config[i/2] >> ((1 - i%2) * 16)
		index, capacity := cfg&0x3f, (cfg>>8)&0xf
		if index == ip12EmptyBank || capacity == 0 {
			continue
		}
		base := index * ip12BankUnit
		if inRange(address, size, base, min((capacity+1)*ip12BankUnit, uint32(len(bank)))) {
			offset := address - base
			return bank[offset : offset+size]
		}
	}
	return nil
}

func (p *ip12PIC) access(address, size, value uint32, write bool) (uint32, bool) {
	offset := address - ip12PICBase
	var reg *uint32
	switch offset &^ 3 {
	case 0:
		reg = &p.control
	case 4:
		return 0x48, !write // Store partial, four-word instruction block.
	case 8:
		return 0x48, !write // Revision B, FPU present, graphics DMA idle.
	case 0x10000, 0x10004:
		reg = &p.config[(offset-0x10000)/4]
	case 0x10200, 0x10204, 0x10208:
		return 0, !write // No memory parity errors pending.
	case 0x10100, 0x10210, 0x20000, 0x20004, 0x20008, 0x2000c:
		return 0, write // Refresh, parity clear and GIO arbitration controls.
	default:
		return 0, false
	}
	shift := (4 - size - (offset & 3)) * 8
	mask := uint32(0xffffffff) >> (32 - 8*size)
	if write {
		*reg = *reg&^(mask<<shift) | (value&mask)<<shift
	}
	return (*reg >> shift) & mask, true
}
