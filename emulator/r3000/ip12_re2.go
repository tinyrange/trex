package r3000

const (
	gr1Width  = 1280
	gr1Height = 1024
)

// RE2 has five interleaved pixel lanes. The framebuffer stores the
// color, overlay and window-ID planes together in each word.
type ip12RE2 struct {
	reg       [64]uint32
	pixels    []uint32
	depth     []uint32
	x, y      int32
	dx, dy    int32
	remaining uint32
	transfer  uint8
	drawn     uint64
}

var re2Mask = [64]uint32{
	0, 0, 0, 0, 1, 1, 15, 3,
	1, 15, 0x7ffffff, 0x3fffff, 3, 0xffff, 0xffff, 0xffffff,
	0x3fff, 0xffffff, 0xfffff, 0xfffff, 0xffffff, 0x7fffff, 0x7ffff, 0x7ffff,
	0xffff, 0xff, 0xffff, 0xffff, 0x7ff, 0xffff, 0x7ff, 7,
	0xffffffff, 0xffffff, 0x1ff, 15, 15, 7, 1, 3,
	0x3f, 1, 1, 1, 1, 1, 15, 15,
	0xff, 1, 3, 0x3ffff, 1, 0x3fff, 1, 0xff,
	3, 0x7ff, 0x7ff, 0xfff, 0xfff, 1, 1, 0,
}

func (r *ip12RE2) canRead(reg uint8) bool {
	return reg != 0x20 || r.transfer == 6 && r.remaining != 0
}

func (r *ip12RE2) canWrite(reg uint8) bool {
	return r.transfer == 0 || reg <= 0x20
}

func (r *ip12RE2) read(reg uint8) uint32 {
	switch reg {
	case 0x0f, 0x10, 0x18, 0x19:
		return r.reg[reg]
	case 0x20:
		if r.transfer == 6 && r.remaining != 0 {
			data := uint32(0)
			if offset, ok := r.locate(r.x>>14, r.y>>14); ok {
				if r.reg[0x25]&3 == 3 {
					if r.depth != nil {
						data = r.depth[offset]
					}
				} else if r.pixels != nil {
					data = r.pixels[offset]
				}
			}
			r.advance()
			return data
		}
	}
	return re2Mask[reg]
}

func (r *ip12RE2) write(reg uint8, value uint32) {
	r.reg[reg] = value & re2Mask[reg]
	switch reg {
	case 0x0a:
		r.reg[0x15] = (value >> 16 & 0xfff) << 11
		r.reg[0x16] = (value >> 8 & 0xff) << 11
		r.reg[0x17] = (value & 0xff) << 11
	case 0x0b:
		r.reg[0x1d] = value & 0xfff
		r.reg[0x1e] = value >> 12 & 0x7ff
	case 0x1f:
		r.draw(uint8(value & 7))
	case 0x20:
		if r.transfer == 7 {
			r.writeTransfer(value)
		}
	}
}

func (r *ip12RE2) locate(x, y int32) (int, bool) {
	return int(y)*gr1Width + int(x), x >= 0 && x < gr1Width && y >= 0 && y < gr1Height
}

func (r *ip12RE2) clipped(x, y int32) bool {
	return x < int32(r.reg[0x3b]) || x > int32(r.reg[0x3c]) ||
		y < int32(r.reg[0x39]) || y > int32(r.reg[0x3a])
}

func (r *ip12RE2) advance() {
	r.x += r.dx
	r.y += r.dy
	r.remaining--
	if r.remaining == 0 {
		r.transfer = 0
	}
}

func (r *ip12RE2) draw(op uint8) {
	x := r.reg[0x1d]
	r.x, r.y = int32((x>>3)*5+(x&7))<<14, int32(r.reg[0x1e])<<14
	r.dx, r.dy = int32(int16(r.reg[0x1a])), int32(int16(r.reg[0x1b]))
	r.remaining = r.reg[0x1c]
	r.transfer = 0
	if r.remaining == 0 {
		return
	}

	switch op {
	case 1, 2, 3:
		r.drawSpan(op)
	case 6, 7:
		r.transfer = op
	}
}

func re2Signed(word uint32, bits uint) int32 {
	return int32(word<<(32-bits)) >> (32 - bits)
}

func (r *ip12RE2) drawSpan(op uint8) {
	red, green, blue := int32(r.reg[0x15]), int32(r.reg[0x16]), int32(r.reg[0x17])
	dr, dg, db := re2Signed(r.reg[0x11], 24), re2Signed(r.reg[0x12], 20), re2Signed(r.reg[0x13], 20)
	x, y := r.x>>14, r.y>>14
	group := int32(1)
	if op == 2 {
		group = 5
	}
	rows := int32(1)
	if op == 3 {
		// On GR1.5 the 20-pixel block spans four adjacent
		// scanlines of the five-lane raster buffer.
		group, rows = 5, 4
		y &^= 3
	}
	mask := r.reg[0x21] | r.reg[0x22]<<24
	aux := r.reg[0x23]<<28 | r.reg[0x24]<<24
	if r.reg[8] == 0 {
		aux = r.reg[0x23]<<28 | (r.reg[0x24]&3)<<26 | r.reg[0x0c]<<24
	}
	pattern := r.reg[0x0e]<<16 | r.reg[0x0d]
	for n := int32(0); n < int32(r.remaining); n++ {
		positionX, positionY := r.x>>14, r.y>>14
		if op != 1 {
			positionX, positionY = x+n, y
		}
		index := n
		if r.reg[0x29] != 0 {
			index = positionX
		}
		if r.reg[0x2a] == 0 || pattern&(1<<(31-(index&31))) != 0 {
			color := uint32(red>>11)&0xfff | (uint32(green>>11)&255)<<8 | (uint32(blue>>11)&255)<<16
			for row := positionY; row < positionY+rows; row++ {
				if !r.clipped(positionX, row) {
					r.store(positionX, row, color, aux, mask, true)
				}
			}
		}
		if (n+1)%group == 0 {
			r.x += r.dx
			r.y += r.dy
			red, green, blue = red+dr, green+dg, blue+db
		}
	}
}

func (r *ip12RE2) store(x, y int32, color, aux, mask uint32, rasterOp bool) {
	offset, ok := r.locate(x, y)
	if !ok || mask == 0 {
		return
	}
	if r.pixels == nil {
		r.pixels = make([]uint32, gr1Width*gr1Height)
	}
	pixel := &r.pixels[offset]
	if r.reg[0x2d] != 0 {
		widMask := uint32(3)
		if r.reg[0x32]&1 != 0 {
			widMask = 15
			if r.reg[0x2f]&8 != 0 {
				widMask = 14
			}
		}
		if (*pixel>>28^r.reg[0x2e])&widMask != 0 {
			return
		}
	}
	if rasterOp {
		var result uint32
		terms := [4]uint32{color & *pixel, color &^ *pixel, *pixel &^ color, ^(color | *pixel)}
		for i, term := range terms {
			if r.reg[6]&(1<<i) != 0 {
				result |= term
			}
		}
		color = result
	}
	*pixel = *pixel&^mask | ((color&0xffffff)|aux)&mask
	r.drawn++
}

func (r *ip12RE2) writeTransfer(word uint32) {
	count := int(r.reg[0x38]) + 1
	if count == 3 {
		count = 1
	}
	for i := 0; i < count && r.remaining != 0; i++ {
		bits := 32 / count
		lane := i
		if r.reg[5] != 0 {
			lane = count - 1 - i
		}
		data := word >> (bits * lane) & uint32((uint64(1)<<bits)-1)
		x, y := r.x>>14, r.y>>14
		if !r.clipped(x, y) {
			switch r.reg[0x25] {
			case 0, 6:
				r.store(x, y, data, 0, r.reg[0x21], false)
			case 1:
				r.store(x, y, 0, data<<24, r.reg[0x22]&3<<24, false)
			case 2:
				mask := r.reg[0x22] & 15
				if r.reg[8] == 0 {
					mask &= 12
				}
				r.store(x, y, 0, data<<24, mask<<24, false)
			case 3, 7:
				if offset, ok := r.locate(x, y); ok {
					if r.depth == nil {
						r.depth = make([]uint32, gr1Width*gr1Height)
					}
					r.depth[offset] = data & 0xffffff
				}
			case 4:
				r.store(x, y, 0, data<<28, r.reg[0x22]&0xf0<<24, false)
			}
		}
		r.advance()
	}
}
