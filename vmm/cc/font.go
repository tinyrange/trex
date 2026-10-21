package cc

import (
	"golang.org/x/text/encoding/charmap"
	"renvo.dev/std/graphics"
	"renvo.dev/std/graphics/gofont"
)

// The PC supplies its own openly licensed BIOS text font, not a host-installed
// font or a copied vendor VGA ROM. Guest font-plane writes still replace it.
var biosTextFont = rasterBIOSFont()

func rasterBIOSFont() [8192]byte {
	var out [8192]byte
	font := gofont.NewMono(14)
	if font == nil {
		panic("embedded Go Mono font is invalid")
	}
	for ch := 32; ch < 256; ch++ {
		pixels := make([]byte, 8*16*4)
		surface := graphics.NewSurfaceBuffer(8, 16, pixels)
		surface.DrawText(font, graphics.Point{X: 0, Y: 13}, string(charmap.CodePage437.DecodeByte(byte(ch))), graphics.White)
		for y := 0; y < 16; y++ {
			for x := 0; x < 8; x++ {
				if pixels[(y*8+x)*4+3] >= 128 {
					out[ch*32+y] |= 0x80 >> uint(x)
				}
			}
		}
	}
	return out
}
func (v *vga) installTextFont() { copy(v.planes[2][:], biosTextFont[:]) }
