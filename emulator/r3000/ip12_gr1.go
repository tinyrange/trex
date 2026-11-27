package r3000

import "image"

// GR1 has two GE5 microcode windows selected by the MAR high bit. The
// second window also exposes the DACs and board control registers.
type ip12GR1 struct {
	bank    uint32
	mar     uint16
	ge      ip12GE5
	raster  ip12RE2
	display [5]byte
	dac     [3]ip12RAMDAC
	cursor  [2]ip12BT431
	xmap    [5]ip12XMAP
}

type ip12RAMDAC struct {
	address byte
	palette [256]byte
	control [16]byte
	overlay [4]byte
}

func (d *ip12RAMDAC) access(index uint32, value byte, write bool) uint32 {
	if index == 0 {
		if write {
			d.address = value
		}
		return uint32(d.address)
	}
	var reg *byte
	switch index {
	case 1:
		reg = &d.palette[d.address]
		d.address++
	case 2:
		reg = &d.control[d.address&15]
	case 3:
		reg = &d.overlay[d.address&3]
		d.address++
	}
	if write {
		*reg = value
	}
	return uint32(*reg)
}

// A pair of BT431s supplies the two cursor bits to all three DACs.
type ip12BT431 struct {
	address uint16
	reg     [16]byte
	ram     [512]byte
}

func (c *ip12BT431) access(index uint32, value byte, write bool) uint32 {
	if index < 2 {
		shift := index * 8
		if write {
			c.address = (c.address&^(0xff<<shift) | uint16(value)<<shift) & 511
		}
		return uint32(byte(c.address >> shift))
	}
	reg := &c.ram[c.address]
	if index == 3 {
		reg = &c.reg[c.address&15]
	}
	if write {
		*reg = value
	}
	c.address = (c.address + 1) & 511
	return uint32(*reg)
}

func (c *ip12BT431) position() (int, int) {
	cx := int(c.reg[1]) | int(c.reg[2]&15)<<8
	cy := int(c.reg[3]) | int(c.reg[4]&15)<<8
	if cy >= 0xfc0 {
		cy -= 0x1000
	}
	delay := [...]int{37, 52, 57, 0}[c.reg[0]>>2&3]
	return cx + delay - 31 - 246, cy + 1 - 39
}

func (c *ip12BT431) active(x, y int) bool {
	if c.reg[0]&0x40 == 0 {
		return false
	}
	cx, cy := c.position()
	x, y = x-cx, y-cy
	if x < 0 || x >= 64 || y < 0 || y >= 64 {
		return false
	}
	return c.ram[y*8+x/8]&(0x80>>(x&7)) != 0
}

func (g *ip12GR1) init() {
	g.display = [5]byte{0x09, 0x08, 0x10, 0, 0x08}
}

func (g *ip12GR1) access(address, size, value uint32, write bool) (uint32, bool) {
	offset := address & 0x7fff
	switch {
	case offset < 0x400 && size == 4:
		g.ge.pc = (g.mar<<8 | uint16(offset/4)) & 0x3fff
		g.ge.hostPC = g.ge.pc
		shift, mask := g.bank*32, uint64(0xffffffff)
		if g.bank != 0 {
			mask = 0xff
			// The ninth host bit selects a long (two-word) microinstruction.
			if value&0x100 != 0 {
				value |= 0x10
			}
		}
		reg := &g.ge.code[g.ge.pc]
		if write {
			*reg = *reg&^(mask<<shift) | (uint64(value)&mask)<<shift
		}
		return uint32(*reg >> shift), true
	case offset >= 0x800 && offset < 0xc00 && size == 4:
		if write {
			g.ge.push(uint64((offset-0x800)/4)<<32 | uint64(value))
		}
		return uint32(g.ge.bus), true
	case offset >= 0xc00 && offset < 0xe00 && size == 4 && write:
		g.mar = uint16((offset - 0xc00) / 4)
		return 0, true
	case (offset == 0xe00 || offset == 0xe04) && size == 4 && write:
		g.bank = offset >> 2 & 1
		return 0, true
	case offset >= 0x1400 && offset < 0x1800 && size == 4 && g.bank == 0:
		g.ge.memptr = (g.mar&0x3f)<<8 | uint16((offset-0x1400)/4)
		reg := &g.ge.data[g.ge.memptr&0x1fff]
		if write {
			*reg = value
		}
		return *reg, true
	case (offset == 0x2000 || offset == 0x2004) && size == 4:
		flag := &g.ge.finish[(offset-0x2000)/4]
		if write {
			*flag = value
		}
		return *flag, true
	}
	if g.bank == 0 {
		return 0, false
	}
	wordOffset := offset &^ 3
	if (size == 4 && offset&3 == 0 || size == 2) && wordOffset >= 0x640 && wordOffset <= 0x780 {
		offset = wordOffset
		if !write && offset == 0x740 {
			pc := uint32(g.ge.pc)
			if size == 4 {
				pc <<= 16
			}
			return pc, true
		}
		if write {
			switch offset {
			case 0x640, 0x700:
				g.ge.wait = ge5Running
			case 0x680:
				g.ge.singleStep = true
			case 0x6c0:
				g.ge.singleStep = false
			case 0x780:
				g.ge.irq = false
			}
			return 0, true
		}
	}
	group := offset &^ 0x1f
	if group >= 0x400 && group <= 0x4a0 && (size == 4 || size == 1 && offset&3 == 3) {
		index := (offset & 31) / 4
		mapSelect := g.display[4]&0x80 != 0
		if group < 0x4a0 {
			return g.xmap[(group-0x400)/0x20].access(index, byte(value), write, mapSelect), true
		}
		if write {
			for i := range g.xmap {
				g.xmap[i].access(index, byte(value), true, mapSelect)
			}
		}
		return 0, write
	}
	if group >= 0x500 && group <= 0x540 && offset&0x10 == 0 && (size == 4 || size == 1 && offset&3 == 3) {
		return g.dac[(group-0x500)/0x20].access((offset&0xf)/4, byte(value), write), true
	}
	if (group == 0x560 || group == 0x580) && offset&0x10 == 0 && (size == 4 || size == 1 && offset&3 == 3) {
		return g.cursor[(group-0x560)/0x20].access((offset&0xf)/4, byte(value), write), true
	}
	var display int
	switch offset &^ 3 {
	case 0x4e0:
		display = 0
	case 0x4c0:
		display = 1
	case 0x5e0:
		display = 2
	case 0x5c0:
		display = 3
	case 0x5a0:
		display = 4
	default:
		return 0, false
	}
	if size != 4 && (size != 1 || offset&3 != 3) {
		return 0, false
	}
	if write {
		mask := byte(0xe7)
		if display == 0 {
			mask = 0xf7
		}
		g.display[display] = g.display[display]&^mask | byte(value)&mask
	}
	result := g.display[display]
	switch display {
	case 3:
		if g.ge.queued != 0 {
			result |= 8
		}
		if g.ge.queued <= 256 {
			result |= 16
		}
	case 4:
		result &= 0x9f
		if g.ge.wait != ge5Halted {
			result |= 16
		}
	}
	return uint32(result), true
}

type ip12XMAP struct {
	address uint16
	color   [8192][3]byte
	overlay [16][3]byte
	mode    [32]byte
	aux     byte
}

func (x *ip12XMAP) access(index uint32, value byte, write, mapSelect bool) uint32 {
	switch index {
	case 0:
		return 0
	case 1, 2, 3:
		var color *byte
		switch {
		case x.address&0x1000 != 0:
			address := x.address
			if !mapSelect {
				address &= 0xfff
			}
			color = &x.color[address][3-index]
		case x.address < 16:
			color = &x.overlay[x.address][3-index]
		default:
			return 0
		}
		if write {
			*color = value
		}
		return uint32(*color)
	case 4:
		if write {
			x.address = (x.address + 1) & 0x1fff
		}
	case 5:
		if x.address < 32 {
			if write {
				if x.address&1 != 0 {
					value &= 0x3f
				}
				x.mode[x.address] = value
			}
			return uint32(x.mode[x.address])
		}
		switch x.address {
		case 32:
			if write {
				x.aux = value & 1
			}
			return uint32(x.aux)
		case 33:
			return 0x18 // Active-low Turbo and Z-buffer options, both absent.
		}
	case 6:
		if write {
			x.address = x.address&0x00ff | uint16(value&31)<<8
		}
		return uint32(x.address >> 8)
	case 7:
		if write {
			x.address = x.address&0x1f00 | uint16(value)
		}
		return uint32(byte(x.address))
	}
	return 0
}

func (g *ip12GR1) screen() *image.RGBA {
	frame := image.NewRGBA(image.Rect(0, 0, gr1Width, gr1Height))
	for y := 0; y < gr1Height; y++ {
		for x := 0; x < gr1Width; x++ {
			pixel := uint32(0)
			if g.raster.pixels != nil {
				pixel = g.raster.pixels[(gr1Height-1-y)*gr1Width+x]
			}
			rgb := g.xmap[x%5].displayColor(pixel, g.display[4]&0x80 != 0)
			i := y*frame.Stride + x*4
			if g.display[2]&1 != 0 {
				cursor := truth(g.cursor[0].active(x, y)) | truth(g.cursor[1].active(x, y))<<1
				for channel, value := range rgb {
					dac := &g.dac[channel]
					color := dac.palette[value]
					if cursor != 0 {
						color = dac.overlay[cursor]
					}
					frame.Pix[i+channel] = color
				}
			}
			frame.Pix[i+3] = 255
		}
	}
	return frame
}

func (x *ip12XMAP) displayColor(pixel uint32, highMap bool) [3]byte {
	wid := (pixel >> 28) * 2
	mode := uint16(x.mode[wid+1])<<8 | uint16(x.mode[wid])
	if uint16(pixel>>20)&mode&0xf0 != 0 || mode&0x100 != 0 && pixel&0xffffff == 0 {
		return x.overlay[pixel>>24&15]
	}
	index := uint16(pixel)
	switch mode & 7 {
	case 0:
		index &= 255
	case 1:
		if mode&8 != 0 {
			index >>= 4
		}
		index &= 15
	case 2:
		if mode&8 != 0 {
			index = uint16(pixel >> 12)
		}
		index &= 0xfff
	case 5:
		if mode&8 == 0 {
			pixel <<= 4
		}
		rgb := [3]byte{byte(pixel), byte(pixel >> 8), byte(pixel >> 16)}
		for i := range rgb {
			rgb[i] = rgb[i]&0xf0 | rgb[i]>>4
		}
		return rgb
	default:
		return [3]byte{byte(pixel), byte(pixel >> 8), byte(pixel >> 16)}
	}
	if mode&0x200 != 0 {
		index = index&255 | (mode&0x3c00)>>2
	}
	if highMap {
		index |= 0x1000
	}
	return x.color[index]
}
