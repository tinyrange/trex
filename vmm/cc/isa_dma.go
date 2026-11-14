package cc

// isaDMA implements the AT's two cascaded 8237 controllers. Audio and other
// ISA peripherals share the same current address/count, mask and TC state.
type isaDMAChannel struct {
	address, baseAddress, count, baseCount uint16
	page, mode                             byte
	masked                                 bool
}
type isaDMA struct {
	channels [8]isaDMAChannel
	high     [2]bool
	terminal [2]byte
	command  [2]byte
}

func newISADMA() *isaDMA {
	d := &isaDMA{}
	for i := range d.channels {
		d.channels[i].masked = true
	}
	return d
}
func dmaPageChannel(port uint16) int {
	switch port {
	case 0x87:
		return 0
	case 0x83:
		return 1
	case 0x81:
		return 2
	case 0x82:
		return 3
	case 0x8f:
		return 4
	case 0x8b:
		return 5
	case 0x89:
		return 6
	case 0x8a:
		return 7
	}
	return -1
}
func (d *isaDMA) port(port uint16, write bool, value byte) (byte, bool) {
	if ch := dmaPageChannel(port); ch >= 0 {
		if write {
			d.channels[ch].page = value
		}
		return d.channels[ch].page, true
	}
	controller, reg := 0, int(port)
	if port >= 0xc0 && port <= 0xde && port&1 == 0 {
		controller, reg = 1, int((port-0xc0)/2)
	} else if port > 15 {
		return 0, false
	}
	base := controller * 4
	if reg < 8 {
		ch := &d.channels[base+reg/2]
		current, initial := &ch.address, &ch.baseAddress
		if reg&1 != 0 {
			current, initial = &ch.count, &ch.baseCount
		}
		shift := uint(0)
		if d.high[controller] {
			shift = 8
		}
		if write {
			*initial = (*initial &^ (uint16(255) << shift)) | uint16(value)<<shift
			*current = *initial
		}
		result := byte(*current >> shift)
		d.high[controller] = !d.high[controller]
		return result, true
	}
	if !write {
		switch reg {
		case 8:
			v := d.terminal[controller]
			d.terminal[controller] = 0
			return v, true
		case 15:
			v := byte(0)
			for i := 0; i < 4; i++ {
				if d.channels[base+i].masked {
					v |= 1 << i
				}
			}
			return v, true
		}
		return 0xff, true
	}
	switch reg {
	case 8:
		d.command[controller] = value
	case 10:
		d.channels[base+int(value&3)].masked = value&4 != 0
	case 11:
		d.channels[base+int(value&3)].mode = value
	case 12:
		d.high[controller] = false
	case 13:
		d.high[controller] = false
		d.command[controller] = 0
		d.terminal[controller] = 0
		for i := 0; i < 4; i++ {
			d.channels[base+i].masked = true
		}
	case 14:
		for i := 0; i < 4; i++ {
			d.channels[base+i].masked = false
		}
	case 15:
		for i := 0; i < 4; i++ {
			d.channels[base+i].masked = value&(1<<i) != 0
		}
	}
	return 0, true
}

// readUnit transfers one byte or word from memory. Count is units minus one;
// word channels ignore page bit zero and retain the AT's 128-KiB wrap.
func (d *isaDMA) readUnit(channel int, ram []byte) ([]byte, bool) {
	if channel < 0 || channel >= 8 || channel == 4 {
		return nil, false
	}
	c := &d.channels[channel]
	if c.masked || d.command[channel/4]&4 != 0 || c.mode&12 != 8 {
		return nil, false
	}
	unit := 1
	address := uint32(c.page)<<16 | uint32(c.address)
	if channel >= 4 {
		unit = 2
		address = uint32(c.page&0xfe)<<16 | uint32(c.address)<<1
	}
	if uint64(address)+uint64(unit) > uint64(len(ram)) {
		return nil, false
	}
	result := ram[address : address+uint32(unit)]
	if c.mode&0x20 != 0 {
		c.address--
	} else {
		c.address++
	}
	if c.count == 0 {
		d.terminal[channel/4] |= 1 << uint(channel&3)
		if c.mode&0x10 != 0 {
			c.address, c.count = c.baseAddress, c.baseCount
		} else {
			c.count = 0xffff
			c.masked = true
		}
	} else {
		c.count--
	}
	return result, true
}
