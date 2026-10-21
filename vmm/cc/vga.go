package cc

import (
	"fmt"
	"image"
	"image/color"

	"golang.org/x/image/font/basicfont"

	"j5.nz/cc/hypervisor"
)

// vga models the standard VGA indexed registers, DAC and four memory planes.
// No SVGA identity is advertised. Register writes determine both memory
// operations and the displayed surface.
type vga struct {
	cgaMono            bool
	planes             [4][65536]byte
	latch              [4]byte
	seq                [8]byte
	gc                 [16]byte
	crtc               [32]byte
	attr               [32]byte
	dac                [256][3]byte
	si, gi, ci, ai     byte
	dacRead, dacWrite  byte
	dacComponent       int
	attrData           bool
	misc, mask, status byte
	text               []byte
	accesses           uint64
}

func newVGA(text []byte) *vga {
	v := &vga{text: text, misc: 0x67, mask: 255}
	v.seq[2] = 3
	v.seq[4] = 2
	v.gc[5] = 0x10
	v.gc[6] = 0x0e
	v.gc[8] = 255
	v.crtc[1] = 79
	v.crtc[0x12] = 0x8f
	v.crtc[7] = 2
	v.crtc[9] = 15
	v.crtc[0x13] = 40
	for i := 0; i < 16; i++ {
		v.attr[i] = byte(i)
		if i >= 8 {
			v.attr[i] += 48
		}
		if i == 6 {
			v.attr[i] = 20
		}
	}
	for i := 0; i < 64; i++ {
		for c := 0; c < 3; c++ {
			level := byte(0)
			if i&(1<<uint(2-c)) != 0 {
				level = 42
			}
			if i&(1<<uint(5-c)) != 0 {
				level += 21
			}
			v.dac[i][c] = level
		}
	}
	for i, index := range []byte{0, 1, 2, 3, 4, 5, 20, 7, 56, 57, 58, 59, 60, 61, 62, 63} {
		v.attr[i] = index
	}
	v.installTextFont()
	return v
}

// Face7x13 is BSD-licensed Go code derived from the public-domain X11
// misc-fixed font. Pad its ASCII glyphs to 8x16 VGA cells. Guest font
// uploads still write plane 2 normally; screenshots never substitute glyphs.
func (v *vga) loadFirmwareFont() {
	face := basicfont.Face7x13
	for ch := 32; ch < 127; ch++ {
		for y := 0; y < 13; y++ {
			var row byte
			for x := 0; x < face.Width; x++ {
				_, _, _, a := face.Mask.At(x, (ch-32)*13+y).RGBA()
				if a != 0 {
					row |= 0x40 >> x
				}
			}
			v.planes[2][ch*32+y+1] = row
		}
	}
}

func (v *vga) setMode(mode byte) error {
	if mode&0x7f != 3 && mode&0x7f != 6 && mode&0x7f != 0x10 && mode&0x7f != 0x12 {
		return fmt.Errorf("unsupported VGA BIOS mode %#x", mode)
	}
	v.cgaMono = mode&0x7f == 6
	if mode&0x80 == 0 {
		if v.cgaMono {
			clear(v.text[:16384])
		}
		for i := range v.planes {
			clear(v.planes[i][:])
		}
	}
	v.installTextFont()
	if v.cgaMono {
		v.seq = [8]byte{3, 0, 1, 0, 6}
		v.gc = [16]byte{0, 0, 0, 0, 0, 0, 0x0d, 0, 255}
		return nil
	}
	if mode&0x7f == 0x10 || mode&0x7f == 0x12 {
		v.misc = 0xe3
		v.seq = [8]byte{3, 1, 15, 0, 6}
		v.gc = [16]byte{0, 0, 0, 0, 0, 0, 5, 15, 255}
		v.crtc = [32]byte{0x5f, 0x4f, 0x50, 0x82, 0x54, 0x80, 0x0b, 0x3e, 0, 0x40, 0, 0, 0, 0, 0, 0, 0xea, 0x8c, 0xdf, 0x28, 0, 0xe7, 4, 0xe3, 0xff}
		if mode&0x7f == 0x10 {
			// Same 80-byte planar scanline, with 350 visible EGA rows.
			v.crtc[0x12] = 0x5d
			v.crtc[7] = (v.crtc[7] &^ 0x42) | 2
		}
		v.attr[0x10] = 1
		v.attr[0x12] = 15
	} else {
		v.seq = [8]byte{3, 0, 3, 0, 2}
		v.gc = [16]byte{0, 0, 0, 0, 0, 0x10, 0x0e, 0, 255}
		v.crtc[1] = 79
		v.crtc[0x12] = 0x8f
		v.crtc[7] = 2
		v.crtc[9] = 15
		v.crtc[0x13] = 40
		v.attr[0x10] = 0
		if mode&0x80 == 0 {
			v.loadFirmwareFont()
		}
	}
	return nil
}

func (v *vga) io(ex hypervisor.X86Exit) error {
	for i := uint32(0); i < ex.Count; i++ {
		for b := uint8(0); b < ex.Size; b++ {
			index := int(i)*int(ex.Size) + int(b)
			port := ex.Port + uint16(b)
			value := ex.Data[index]
			if ex.Write {
				switch port {
				case 0x3c0:
					if !v.attrData {
						v.ai = value & 31
					} else {
						v.attr[v.ai] = value
					}
					v.attrData = !v.attrData
				case 0x3c2:
					v.misc = value
				case 0x3c4:
					v.si = value & 7
				case 0x3c5:
					v.seq[v.si] = value
				case 0x3ce:
					v.gi = value & 15
				case 0x3cf:
					v.gc[v.gi] = value
				case 0x3d4, 0x3b4:
					v.ci = value & 31
				case 0x3d5, 0x3b5:
					v.crtc[v.ci] = value
				case 0x3c6:
					v.mask = value
				case 0x3c7:
					v.dacRead = value
					v.dacComponent = 0
				case 0x3c8:
					v.dacWrite = value
					v.dacComponent = 0
				case 0x3c9:
					v.dac[v.dacWrite][v.dacComponent] = value & 63
					v.dacComponent++
					if v.dacComponent == 3 {
						v.dacComponent = 0
						v.dacWrite++
					}
				}
			} else {
				value = 0xff
				switch port {
				case 0x3c0:
					value = v.ai
				case 0x3c1:
					value = v.attr[v.ai]
				case 0x3c2:
					value = 0x10
				case 0x3cc:
					value = v.misc
				case 0x3c4:
					value = v.si
				case 0x3c5:
					value = v.seq[v.si]
				case 0x3ce:
					value = v.gi
				case 0x3cf:
					value = v.gc[v.gi]
				case 0x3d4, 0x3b4:
					value = v.ci
				case 0x3d5, 0x3b5:
					value = v.crtc[v.ci]
				case 0x3c6:
					value = v.mask
				case 0x3c7:
					value = 3
				case 0x3c8:
					value = v.dacWrite
				case 0x3c9:
					value = v.dac[v.dacRead][v.dacComponent]
					v.dacComponent++
					if v.dacComponent == 3 {
						v.dacComponent = 0
						v.dacRead++
					}
				case 0x3da, 0x3ba:
					v.status ^= 9
					value = v.status
					v.attrData = false
				}
				ex.Data[index] = value
			}
		}
	}
	return nil
}

func (v *vga) offset(address uint64) (uint32, bool) {
	base, size := uint64(0xa0000), uint64(0x20000)
	switch (v.gc[6] >> 2) & 3 {
	case 1:
		size = 0x10000
	case 2:
		base, size = 0xb0000, 0x8000
	case 3:
		base, size = 0xb8000, 0x8000
	}
	if address < base || address >= base+size {
		return 0, false
	}
	return uint32(address - base), true
}
func (v *vga) read(address uint64) byte {
	if v.cgaMono && address >= 0xb8000 && address < 0xbc000 {
		return v.text[address-0xb8000]
	}
	v.accesses++
	off, ok := v.offset(address)
	if !ok {
		return 255
	}
	plane := v.gc[4] & 3
	if v.seq[4]&8 != 0 {
		plane = byte(off & 3)
		off >>= 2
	} else if v.gc[5]&0x10 != 0 {
		plane = (plane & 2) | byte(off&1)
		off >>= 1
	}
	off &= 65535
	for i := range v.latch {
		v.latch[i] = v.planes[i][off]
	}
	if v.gc[5]&8 == 0 {
		return v.latch[plane]
	}
	result := byte(255)
	for i := 0; i < 4; i++ {
		if v.gc[7]&(1<<i) != 0 {
			if v.gc[2]&(1<<i) != 0 {
				result &= v.latch[i]
			} else {
				result &= ^v.latch[i]
			}
		}
	}
	return result
}
func (v *vga) write(address uint64, value byte) {
	if v.cgaMono && address >= 0xb8000 && address < 0xbc000 {
		v.text[address-0xb8000] = value
		return
	}
	v.accesses++
	off, ok := v.offset(address)
	if !ok {
		return
	}
	mask := v.seq[2] & 15
	if v.seq[4]&8 != 0 {
		mask &= 1 << uint(off&3)
		off >>= 2
	} else if v.seq[4]&4 == 0 {
		mask &= 5 << uint(off&1)
		off >>= 1
	}
	off &= 65535
	rotate := v.gc[3] & 7
	rotated := value>>rotate | value<<(8-rotate)
	for i := 0; i < 4; i++ {
		if mask&(1<<i) == 0 {
			continue
		}
		data, bits := rotated, v.gc[8]
		switch v.gc[5] & 3 {
		case 0:
			if v.gc[1]&(1<<i) != 0 {
				data = 0
				if v.gc[0]&(1<<i) != 0 {
					data = 255
				}
			}
		case 1:
			v.planes[i][off] = v.latch[i]
			continue
		case 2:
			data = 0
			if value&(1<<i) != 0 {
				data = 255
			}
		case 3:
			bits &= rotated
			data = 0
			if v.gc[0]&(1<<i) != 0 {
				data = 255
			}
		}
		switch (v.gc[3] >> 3) & 3 {
		case 1:
			data &= v.latch[i]
		case 2:
			data |= v.latch[i]
		case 3:
			data ^= v.latch[i]
		}
		v.planes[i][off] = (data & bits) | (v.latch[i] &^ bits)
	}
	if address >= 0xb8000 && address < 0xc0000 && v.gc[6]&1 == 0 && off < 16384 {
		v.text[off*2] = v.planes[0][off]
		v.text[off*2+1] = v.planes[1][off]
	}
}

func (v *vga) syncText() {
	for i := 0; i < len(v.text)/2; i++ {
		v.planes[0][i] = v.text[i*2]
		v.planes[1][i] = v.text[i*2+1]
	}
}
func (v *vga) mmio(ex hypervisor.X86Exit, cpu hypervisor.X86) error {
	if ex.Address < 0xa0000 || ex.Address+uint64(ex.Size) > 0xc0000 {
		return fmt.Errorf("unhandled MMIO address=%#x size=%d write=%t", ex.Address, ex.Size, ex.Write)
	}
	var result uint64
	for i := uint8(0); i < ex.Size; i++ {
		if ex.Write {
			v.write(ex.Address+uint64(i), ex.Data[i])
		} else {
			result |= uint64(v.read(ex.Address+uint64(i))) << (8 * i)
		}
	}
	if !ex.Write {
		cpu.CompleteMMIORead(result, uint32(ex.Size))
	}
	return nil
}

// Expand the emulated six-bit DAC output to the eight-bit screenshot surface.
// The low DAC bit also supplies the two low output bits, matching the QEMU
// comparison surface; proportional scaling changes even the default colors.
func dacComponent(value byte) byte {
	value &= 63
	level := value * 4
	if value&1 != 0 {
		level += 3
	}
	return level
}

func (v *vga) screenshot() (*image.RGBA, error) {
	if v.cgaMono {
		img := image.NewRGBA(image.Rect(0, 0, 640, 200))
		for y := 0; y < 200; y++ {
			for x := 0; x < 640; x++ {
				off := (y&1)*8192 + (y/2)*80 + x/8
				level := byte(0)
				if v.text[off]&(0x80>>uint(x&7)) != 0 {
					level = 255
				}
				img.SetRGBA(x, y, color.RGBA{R: level, G: level, B: level, A: 255})
			}
		}
		return img, nil
	}
	width := (int(v.crtc[1]) + 1) * 8
	height := int(v.crtc[0x12]) | int(v.crtc[7]&2)<<7 | int(v.crtc[7]&0x40)<<3
	height++
	if width < 8 || width > 2048 || height < 1 || height > 2048 {
		return nil, fmt.Errorf("invalid VGA dimensions %dx%d", width, height)
	}
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	start := (int(v.crtc[0x0c]) << 8) | int(v.crtc[0x0d])
	stride := int(v.crtc[0x13]) * 2
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			var index byte
			if v.gc[6]&1 == 0 {
				charHeight := int(v.crtc[9]&31) + 1
				off := (start + (y/charHeight)*stride + x/8) & 65535
				ch, attr := v.planes[0][off], v.planes[1][off]
				glyph := v.planes[2][int(ch)*32+y%charHeight]
				index = attr >> 4 & 15
				if glyph&(0x80>>uint(x&7)) != 0 {
					index = attr & 15
				}
			} else {
				off := (start + y*stride + x/8) & 65535
				for plane := 0; plane < 4; plane++ {
					if v.planes[plane][off]&(0x80>>uint(x&7)) != 0 {
						index |= 1 << plane
					}
				}
			}
			index = v.attr[index] & 63
			if v.attr[0x10]&0x80 != 0 {
				index = (index & 15) | (v.attr[0x14]&3)<<4
			}
			index |= (v.attr[0x14] & 12) << 4
			index &= v.mask
			c := v.dac[index]
			img.SetRGBA(x, y, color.RGBA{R: dacComponent(c[0]), G: dacComponent(c[1]), B: dacComponent(c[2]), A: 255})
		}
	}
	return img, nil
}
