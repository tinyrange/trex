package cc

import (
	"golang.org/x/text/encoding/charmap"
	"renvo.dev/std/graphics"
	"renvo.dev/std/graphics/gofont"
)

func rasterBIOSFontHeight(height int) []byte {
	out := make([]byte, 256*height)
	font := gofont.NewMono(graphics.Scalar(max(7, height-2)))
	for ch := 32; ch < 256; ch++ {
		pixels := make([]byte, 8*height*4)
		surface := graphics.NewSurfaceBuffer(8, height, pixels)
		surface.DrawText(font, graphics.Point{X: 0, Y: graphics.Scalar(height - 2)}, string(charmap.CodePage437.DecodeByte(byte(ch))), graphics.White)
		for y := 0; y < height; y++ {
			for x := 0; x < 8; x++ {
				if pixels[(y*8+x)*4+3] >= 128 {
					out[ch*height+y] |= 0x80 >> uint(x)
				}
			}
		}
	}
	return out
}
