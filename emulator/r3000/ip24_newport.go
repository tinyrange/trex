package r3000

import (
	"image"
	"math/bits"
)

const (
	newportBase   = 0x1f0f0000
	newportWidth  = 1280
	newportHeight = 1024
	newportStride = newportWidth + 64
	newportRows   = newportHeight + 64
	newportFrame  = ip24Clock / 60
)

// The XL24 combines REX3 drawing and host transfers with separate
// RGB and auxiliary bitplanes and a VC2/XMAP9 display controller.
type newport struct {
	reg                  [0x1400 / 4]uint32
	rgb, aux             []uint32
	vc2                  [32]uint16
	vc2RAM               [0x8000]uint16
	vc2Index             byte
	dcbPort              uint32
	xmap                 [2]newportXMAP
	cmap                 [2]newportCMAP
	nextRetrace, timeout uint64
	retrace              bool
	commands, drawn      uint64
}

type newportXMAP struct {
	reg   [8]byte
	modes [32]uint32
}

type newportCMAP struct {
	index   uint16
	palette [0x10000]uint32
}

func (g *newport) reset() {
	rgb, aux := g.rgb, g.aux
	if rgb == nil {
		rgb, aux = make([]uint32, newportStride*newportRows), make([]uint32, newportStride*newportRows)
	}
	clear(rgb)
	clear(aux)
	*g = newport{rgb: rgb, aux: aux, nextRetrace: newportFrame}
	g.reg[0x1324/4] = 0x10001000
	g.reg[0x220/4] = 0xffffff
	g.reg[0] = 0x3002f001
}

func (g *newport) tick(cycles uint64) {
	if cycles >= g.nextRetrace {
		g.nextRetrace += newportFrame
		g.retrace = g.retrace || g.vc2[0x10]&1 != 0
	}
}

func (g *newport) access(offset, size uint32, data uint64, write bool, cycles uint64) (uint64, bool) {
	if (size != 1 && size != 2 && size != 4 && size != 8) || offset&(size-1) != 0 {
		return 0, false
	}
	reg := offset &^ 0x803
	if reg+max(4, size) > uint32(len(g.reg))*4 {
		return 0, false
	}
	var result uint64
	switch {
	case size < 4:
		shift := (4 - size - (offset & 3)) * 8
		mask := uint32(1)<<(size*8) - 1
		if write {
			g.write(reg, g.reg[reg/4]&^(mask<<shift)|(uint32(data)&mask)<<shift, cycles)
		} else {
			result = uint64(g.read(reg, cycles) >> shift & mask)
		}
	case write:
		if size == 8 {
			g.write(reg, uint32(data>>32), cycles)
			reg += 4
		}
		g.write(reg, uint32(data), cycles)
	default:
		result = uint64(g.read(reg, cycles))
		if size == 8 {
			result = result<<32 | uint64(g.read(reg+4, cycles))
		}
	}
	if offset&0x800 != 0 && reg < 0x300 {
		g.execute()
	}
	return result, true
}

func (g *newport) read(reg uint32, cycles uint64) uint32 {
	switch reg {
	case 0x240:
		return g.dcb(0, false, cycles)
	case 0x1338, 0x133c:
		status := uint32(3)
		if g.retrace {
			status |= 0x20
		}
		if cycles < g.timeout {
			status |= 0x10
		}
		if reg == 0x1338 {
			g.retrace = false
		}
		return status
	}
	return g.reg[reg/4]
}

func (g *newport) coordinates(first bool, x, y int16) {
	i := 0x100 / 4
	if !first {
		i += 2
	}
	g.reg[i] = uint32(x) << 11 & 0x07ffff80
	g.reg[i+1] = uint32(y) << 11 & 0x07ffff80
	g.syncCoordinates()
}

func (g *newport) syncCoordinates() {
	x1, y1, x2, y2 := g.reg[0x100/4], g.reg[0x104/4], g.reg[0x108/4], g.reg[0x10c/4]
	g.reg[0x138/4], g.reg[0x13c/4], g.reg[0x140/4], g.reg[0x144/4] = x1&0x7fff80, y1&0x7fff80, x2&0x7fff80, y2&0x7fff80
	g.reg[0x148/4], g.reg[0x14c/4] = x1>>11, x2&0x7fff80
	g.reg[0x150/4], g.reg[0x154/4] = x1>>11<<16|y1>>11, x2>>11<<16|y2>>11
	g.reg[0x158/4] = x1>>11<<16 | x2>>11
}

func (g *newport) write(reg, value uint32, cycles uint64) {
	g.reg[reg/4] = value
	switch reg {
	case 0x100, 0x104, 0x108, 0x10c:
		g.reg[reg/4] &= 0x07ffff80
		g.syncCoordinates()
		if reg == 0x100 {
			g.reg[0x110/4] = g.reg[0x148/4]
		}
	case 0x138, 0x13c, 0x140, 0x144, 0x14c:
		index := (reg - 0x138) / 4
		if reg == 0x14c {
			index = 2
		}
		g.write(0x100+index*4, value&0x7fff80, cycles)
	case 0x148, 0x150:
		x, y := int16(value), int16(g.reg[0x104/4]>>11)
		if reg == 0x150 {
			x, y = int16(value>>16), int16(value)
		}
		g.coordinates(true, x, y)
		g.reg[0x110/4] = uint32(uint16(x))
	case 0x154:
		g.coordinates(false, int16(value>>16), int16(value))
	case 0x158:
		g.coordinates(true, int16(value>>16), int16(g.reg[0x104/4]>>11))
		g.coordinates(false, int16(value), int16(g.reg[0x10c/4]>>11))
		g.reg[0x110/4] = value >> 16
	case 0x200:
		if g.reg[0]&0x8000 == 0 {
			g.reg[0x224/4] = value >> 11
		}
	case 0x224:
		if g.reg[0]&0x8000 != 0 {
			g.reg[0x200/4] = uint32(byte(value)) << 11
			g.reg[0x208/4] = uint32(byte(value>>8)) << 11
			g.reg[0x20c/4] = uint32(byte(value>>16)) << 11
		}
	case 0x238:
		g.dcbPort = value >> 4 & 7
	case 0x240:
		g.dcb(value, true, cycles)
	}
}

func (g *newport) dcb(value uint32, write bool, cycles uint64) uint32 {
	mode := g.reg[0x238/4]
	port := g.dcbPort
	device := mode >> 7 & 15
	if mode&8 != 0 {
		g.dcbPort = (port + 1) & 7
	}
	switch device {
	case 0:
		return g.video(port, mode&3, value, write, cycles)
	case 1, 2, 3:
		if device == 1 && write {
			g.cmap[1].access(port, value, true)
		}
		return g.cmap[truth(device == 3)].access(port, value, write)
	case 4, 5, 6:
		if device == 4 && write {
			g.xmap[1].access(port, value, true)
		}
		return g.xmap[truth(device == 6)].access(port, value, write)
	case 10:
		g.timeout = cycles + ip24Clock/1000 // Presenter is disconnected.
	}
	return 0
}

func (g *newport) video(port, width, value uint32, write bool, cycles uint64) uint32 {
	switch port {
	case 0:
		if write {
			if width == 1 {
				g.vc2Index = byte(value)
			} else if width == 0 || width == 3 {
				g.vc2Index = byte(value >> 24)
				if g.vc2Index < 32 {
					g.vc2[g.vc2Index] = uint16(value >> 8)
				}
			}
		}
	case 1:
		if !write && g.vc2Index < 32 {
			if g.vc2Index == 0x0b {
				return uint32(cycles%newportFrame) * 1065 / newportFrame
			}
			return uint32(g.vc2[g.vc2Index])
		}
	case 3:
		addr := g.vc2[7] & 0x7fff
		g.vc2[7] = (addr + 1) & 0x7fff
		if write {
			g.vc2RAM[addr] = uint16(value)
		}
		return uint32(g.vc2RAM[addr])
	}
	return 0
}

func (x *newportXMAP) access(port, value uint32, write bool) uint32 {
	if write {
		switch port {
		case 0, 3, 4, 7:
			x.reg[port] = byte(value)
		case 5:
			x.modes[value>>24&31] = value & 0xffffff
		}
		return 0
	}
	switch port {
	case 1:
		return 3
	case 2:
		return 2
	case 5:
		index := x.reg[7]
		if index&3 < 3 {
			return x.modes[index>>2&31] >> (8 * (2 - (index & 3))) & 255
		}
	}
	return uint32(x.reg[port])
}

func (c *newportCMAP) access(port, value uint32, write bool) uint32 {
	if write {
		switch port {
		case 0:
			c.index = uint16(value)
		case 2:
			c.palette[c.index] = value >> 8
		}
	} else {
		switch port {
		case 4:
			return 8
		case 6:
			return 0x42 // NG1 board revision 4, 24-bit VRAM, CMAP revision 2.
		}
	}
	return 0
}

func (g *newport) screen() *image.RGBA {
	return g.screenInto(nil)
}

func (g *newport) screenInto(out *image.RGBA) *image.RGBA {
	bounds := image.Rect(0, 0, newportWidth, newportHeight)
	if out == nil || out.Bounds() != bounds {
		out = image.NewRGBA(bounds)
	}
	xmap, cmap := &g.xmap[0], &g.cmap[0]
	for y := range newportHeight {
		did := g.vc2RAM[(int(g.vc2[5])+y)&0x7fff] & 0x7fff
		mode := xmap.modes[g.vc2RAM[did]&31]
		did++
		for x := range newportWidth {
			entry := g.vc2RAM[did&0x7fff]
			if x != 0 && int(entry>>5) == x {
				mode = xmap.modes[entry&31]
				did++
			}
			pixel := g.rgb[y*newportStride+x]
			depth := [...]uint{4, 8, 12, 24}[mode>>10&3]
			if mode&1 != 0 && depth < 24 {
				pixel >>= depth
			}
			pixel &= (1 << depth) - 1
			color := uint32(0)
			if mode&0x300 == 0 {
				color = cmap.palette[(mode&0xf8)<<5|pixel&0xffff]
			} else if depth == 24 {
				color = bits.ReverseBytes32(pixel) >> 8
			} else {
				color = newportDirectColor(pixel, depth)
			}
			if cursor := g.cursorPixel(x, y); cursor != 0 {
				color = cmap.palette[uint16(xmap.reg[3])<<5|uint16(cursor)]
			}
			i := y*out.Stride + 4*x
			out.Pix[i], out.Pix[i+1], out.Pix[i+2], out.Pix[i+3] = byte(color>>16), byte(color>>8), byte(color), 255
		}
	}
	return out
}

func (g *newport) cursorPixel(x, y int) byte {
	control := g.vc2[0x10]
	if control&0x190 != 0x90 {
		return 0
	}
	size := 32
	if control&0x200 != 0 {
		size = 64
	}
	x, y = x-int(g.vc2[2])+size-1, y-int(g.vc2[3])+size-1
	if uint(x) >= uint(size) || uint(y) >= uint(size) {
		return 0
	}
	addr := (int(g.vc2[1]) + y*(size/16) + x/16) & 0x7fff
	shift := uint(15 - (x & 15))
	first := byte(g.vc2RAM[addr] >> shift & 1)
	if size == 64 {
		return first
	}
	return first | byte(g.vc2RAM[(addr+64)&0x7fff]>>shift&1)<<1
}

func newportDirectColor(p uint32, depth uint) uint32 {
	switch depth {
	case 4:
		return (p&1)*0xff0000 | (p>>1&1)*0xff00 | p>>2&1*0xff
	case 8:
		return (p&7)*255/7<<16 | (p>>3&7)*255/7<<8 | (p>>6&3)*85
	default:
		return (p&15)*17<<16 | (p>>4&15)*17<<8 | (p>>8&15)*17
	}
}
