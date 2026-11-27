package r3000

import "math/bits"

func (g *newport) execute() {
	mode, format := g.reg[1], g.reg[0]
	op, addressing := mode&3, mode>>2&7
	if op == 0 {
		return
	}
	g.commands++
	start, end := g.reg[0x150/4], g.reg[0x154/4]
	x, y := int(int16(start>>16)), int(int16(start))
	xEnd, yEnd := int(int16(end>>16)), int(int16(end))
	raster := g.raster(format)
	if addressing >= 2 {
		if op == 2 && addressing <= 4 {
			g.line(raster, x, y, xEnd, yEnd, mode)
		}
		return
	}

	dx, dy := 1, 1
	if x > xEnd {
		dx = -1
	}
	if y > yEnd {
		dy = -1
	}
	if mode&0x80000 != 0 && dx < 0 {
		return
	}
	hostColor := op == 2 && mode&0x40 != 0
	packed := format&0x80 != 0
	width, height := 1, 1
	if mode&0x100 != 0 || op == 1 || hostColor && packed {
		width = (xEnd-x)*dx + 1
	}
	if addressing == 1 && mode&0x200 != 0 {
		height = (yEnd-y)*dy + 1
	}
	if mode&0x8000 != 0 {
		width = min(width, 32)
	}
	host := uint64(g.reg[0x230/4])<<32 | uint64(g.reg[0x234/4])
	unit := [...]int{8, 8, 16, 32}[format>>8&3]
	hostCount := 1
	if packed {
		words := 32
		if format&0x400 != 0 {
			words = 64
		}
		hostCount = words / unit
	}
	if op == 1 || hostColor && packed {
		width, height = min(width, hostCount), 1
	}
	if format&0x800 != 0 {
		host = bits.ReverseBytes64(host)
	}
	pattern := uint32(0xffffffff)
	if mode&0x1000 != 0 {
		pattern = g.reg[0x14/4]
	} else if mode&0x2000 != 0 {
		pattern = g.reg[0x0c/4]
	}
	move := g.reg[0x114/4]
	moveX, moveY := int(int16(move>>16)), int(int16(move))
	hostResult := uint64(0)
	color := g.color(format)
	// Unclipped coordinates are signed 16-bit. Limit the iteration to
	// the backing store, using destination coordinates for screen copies.
	xOffset, yOffset := raster.xOffset, raster.yOffset
	if op == 3 {
		xOffset, yOffset = xOffset+moveX, yOffset+moveY
	}
	minColumn, maxColumn := newportVisible(x+xOffset, dx, width, newportStride)
	minRow, maxRow := newportVisible(y+yOffset, dy, height, newportRows)
	for row := minRow; row < maxRow; row++ {
		py := y + row*dy
		for column := minColumn; column < maxColumn; column++ {
			px := x + column*dx
			switch op {
			case 1:
				value := raster.pixel(px, py)
				shift := 0
				if packed {
					shift = 64 - (column+1)*unit
				} else {
					shift = 32
				}
				hostResult |= uint64(value) & ((1 << unit) - 1) << shift
			case 2:
				if pattern&(1<<(31-uint(column&31))) == 0 {
					if mode&0x30000 != 0 {
						raster.put(px, py, g.reg[0x18/4])
					}
					continue
				}
				if hostColor {
					shift := 32
					if packed {
						shift = 64 - (column+1)*unit
					}
					color = uint32(host>>shift) & uint32((1<<unit)-1)
				}
				raster.put(px, py, color)
			case 3:
				raster.put(px+moveX, py+moveY, raster.pixel(px, py))
			}
		}
	}
	if op == 1 {
		if format&0x800 != 0 {
			hostResult = bits.ReverseBytes64(hostResult)
		}
		g.reg[0x230/4], g.reg[0x234/4] = uint32(hostResult>>32), uint32(hostResult)
	}
	nextX, nextY := x+width*dx, y
	if addressing == 1 && (nextX-xEnd)*dx > 0 {
		nextX, nextY = int(int16(g.reg[0x110/4])), y+height*dy
	}
	g.coordinates(true, int16(nextX), int16(nextY))
}

func newportVisible(start, step, count, extent int) (int, int) {
	if step > 0 {
		return max(0, -start), min(count, extent-start)
	}
	return max(0, start-extent+1), min(count, start+1)
}

func absInt(value int) int {
	return max(value, -value)
}

func (g *newport) line(r newportRaster, x, y, xEnd, yEnd int, mode uint32) {
	dx, dy := absInt(xEnd-x), -absInt(yEnd-y)
	stepX, stepY := -1, -1
	if x < xEnd {
		stepX = 1
	}
	if y < yEnd {
		stepY = 1
	}
	err := dx + dy
	color := g.color(g.reg[0])
	for i := 0; ; i++ {
		last := x == xEnd && y == yEnd
		if !(i == 0 && mode&0x400 != 0 || last && mode&0x800 != 0) {
			r.put(x, y, color)
		}
		if last {
			break
		}
		twice := 2 * err
		if twice >= dy {
			err += dy
			x += stepX
		}
		if twice <= dx {
			err += dx
			y += stepY
		}
	}
	g.coordinates(true, int16(x), int16(y))
}

func (g *newport) color(format uint32) uint32 {
	if format&0x20000 != 0 {
		return g.reg[0x1c/4]
	}
	if format&0x8000 == 0 {
		return g.reg[0x224/4]
	}
	red := g.reg[0x200/4] >> 11 & 0xff
	green := g.reg[0x208/4] >> 11 & 0xff
	blue := g.reg[0x20c/4] >> 11 & 0xff
	if format>>3&3 == 2 {
		// Each 12-bit buffer stores the high nibble of each component.
		return (blue&0xf0)<<4 | green&0xf0 | red>>4
	}
	return blue<<16 | green<<8 | red
}

type newportRaster struct {
	board             *newport
	buffer            []uint32
	mask              uint32
	depth, shift, rop uint
	xOffset, yOffset  int
}

func (g *newport) raster(format uint32) newportRaster {
	window := g.reg[0x1324/4]
	r := newportRaster{
		board: g, mask: g.reg[0x220/4], rop: uint(format >> 28),
		depth:   [...]uint{4, 8, 12, 24}[format>>3&3],
		xOffset: int(int16(window>>16)) - 0x1000, yOffset: int(int16(window)) - 0x1000,
	}
	switch format & 7 {
	case 1, 2:
		r.buffer = g.rgb
		r.mask &= 0xffffff
	case 4:
		r.buffer, r.shift = g.aux, 8
		r.mask &= 0xf00
	case 5:
		r.buffer, r.shift = g.aux, 2
		r.mask &= 0xcc
	case 6:
		r.buffer = g.aux
		r.mask &= 0x33
	}
	if format&0x20 != 0 && r.depth < 24 {
		r.shift += r.depth
	}
	return r
}

func (r newportRaster) pixel(x, y int) uint32 {
	x, y = x+r.xOffset, y+r.yOffset
	if r.buffer == nil || uint(x) >= newportStride || uint(y) >= newportRows {
		return 0
	}
	return r.buffer[y*newportStride+x] >> r.shift & ((1 << r.depth) - 1)
}

func (r newportRaster) put(x, y int, src uint32) {
	if r.buffer == nil || r.mask == 0 || !r.board.clip(x, y) {
		return
	}
	x, y = x+r.xOffset, y+r.yOffset
	if uint(x) >= newportStride || uint(y) >= newportRows {
		return
	}
	src &= (1 << r.depth) - 1
	for lane := r.depth; lane < 24; lane *= 2 {
		src |= src << lane
	}
	src <<= r.shift
	i := y*newportStride + x
	dst := r.buffer[i]
	result := uint32(0)
	if r.rop&1 != 0 {
		result |= src & dst
	}
	if r.rop&2 != 0 {
		result |= src &^ dst
	}
	if r.rop&4 != 0 {
		result |= dst &^ src
	}
	if r.rop&8 != 0 {
		result |= ^(src | dst)
	}
	r.buffer[i] = dst&^r.mask | result&r.mask
	r.board.drawn++
}

func (g *newport) clip(x, y int) bool {
	mode := g.reg[0x1328/4] & 31
	inside := func(offset uint32, x, y int) bool {
		h, v := g.reg[offset/4], g.reg[offset/4+1]
		return x >= int(int16(h>>16)) && x <= int(int16(h)) && y >= int(int16(v>>16)) && y <= int(int16(v))
	}
	if mode&1 != 0 && !inside(0x28, x, y) {
		return false
	}
	if mode&30 == 0 {
		return true
	}
	window := g.reg[0x1324/4]
	x, y = x+int(int16(window>>16)), y+int(int16(window))
	for i := range uint32(4) {
		if mode&(2<<i) != 0 && inside(0x1300+8*i, x, y) {
			return true
		}
	}
	return false
}
