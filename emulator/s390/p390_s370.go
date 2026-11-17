package s390

import "encoding/binary"

func (p *P390) catalogEntry(n uint16) []byte {
	if n >= 512 {
		return nil
	}
	s := p.Aperture[p390Subchannels+int(n)*64 : p390Subchannels+(int(n)+1)*64]
	if s[5]&1 == 0 || binary.LittleEndian.Uint32(s[0x34:]) == 0xffffffff {
		return nil
	}
	return s
}

func (p *P390) device370(dev uint16) (uint16, []byte) {
	for n := uint16(0); n < 512; n++ {
		s := p.catalogEntry(n)
		if s != nil && binary.BigEndian.Uint16(s[6:]) == dev {
			return n, s
		}
	}
	return 0, nil
}

func (p *P390) accept370(n uint16) {
	x := &p.interrupts[n]
	x.pending, x.irq = false, false
	x.fc, x.ac, x.sc = 0, 0, 0
	clear(p.Aperture[p390Subchannels+int(n)*64+0x1c : p390Subchannels+int(n)*64+0x20])
}

// io370 translates classic channel instructions into the same original-host
// assists used by SSCH. No native channel device is installed or executed.
func (p *P390) io370(c *CPU, op []byte, dev uint16) {
	if op[0] == 0x9f { // TCH
		c.PSW.CC = 3
		for n := uint16(0); n < 512; n++ {
			s := p.catalogEntry(n)
			if s == nil || uint16(s[6]) != dev>>8 {
				continue
			}
			if c.PSW.CC == 3 {
				c.PSW.CC = 0
			}
			if p.interrupts[n].pending {
				c.PSW.CC = 1
			}
		}
		return
	}
	n, s := p.device370(dev)
	if s == nil {
		c.PSW.CC = 3
		return
	}
	x := &p.interrupts[n]
	x.devno = dev
	if x.pending {
		c.storeCSW(x)
		if op[0] == 0x9c {
			c.setLowByte(0x44, x.devStatus|usBusy)
		}
		p.accept370(n)
		c.PSW.CC = 1
		return
	}
	if op[0] == 0x9d { // TIO/CLRIO: consume status above, otherwise idle/busy.
		c.PSW.CC = 0
		if x.fc != 0 || x.ac != 0 {
			c.PSW.CC = 2
		}
		return
	}
	if op[0] == 0x9e { // HIO/HDV uses the original HSCH assist when active.
		c.PSW.CC = 0
		if x.fc != 0 || x.ac != 0 {
			p.postChannel(c, 0xb231, 0, n)
		}
		return
	}
	if x.fc != 0 || x.ac != 0 {
		c.PSW.CC = 2
		return
	}
	caw := c.lowWord(0x48)
	if caw&0x0f000007 != 0 {
		x.key = byte(caw >> 28)
		x.ccwaddr = 0
		x.devStatus = 0
		x.schStatus = scsProgramCheck
		x.residual = 0
		c.storeCSW(x)
		c.PSW.CC = 1
		return
	}
	s[5] |= 0x80
	clear(s[0x1c:0x28])
	s[0x1c] = byte(caw>>24) & 0xf0
	binary.BigEndian.PutUint32(s[0x20:], caw&0x00fffff8)
	binary.BigEndian.PutUint32(p.Aperture[p390Combuf+0xc:], caw)
	x.enabled = true
	x.key = byte(caw >> 28)
	x.fc = fcStart
	p.postChannel(c, 0xb233, 0, n)
}

func (p *P390) takeIO370(c *CPU) bool {
	for n := range p.interrupts {
		x := &p.interrupts[n]
		if !x.pending || !x.irq || !x.enabled || !c.channelEnabled(x.devno>>8) {
			continue
		}
		c.PSW.Wait = false
		c.storeCSW(x)
		p.accept370(uint16(n))
		if c.PSW.BC {
			c.PSW.IntCode = x.devno
		} else {
			c.setLowHalf(0xba, x.devno)
		}
		c.M.Interrupts["io"]++
		c.swap(pswIOOld, pswIONew)
		return true
	}
	return false
}
