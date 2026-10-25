package ramfb

import (
	"encoding/binary"
	"image"
)

// CUR1 is an optional monochrome hardware cursor in the TRF1 header. At
// offset 512: magic, active (uint32); signed x/y (int16); four reserved bytes;
// signed hotspot x/y, width, height, stride, reserved (uint16); AND then XOR
// masks, each 128 bytes. Shapes are 32x32, MSB first, with four-byte rows.
// The guest clears active before changing shape and publishes active last.
const CursorMagic uint32 = 0x31525543

func compositeCursor(frame *image.RGBA, memory []byte) {
	c := memory[512:]
	if binary.LittleEndian.Uint32(c) != CursorMagic || binary.LittleEndian.Uint32(c[4:]) != 1 ||
		binary.LittleEndian.Uint16(c[20:]) != 32 || binary.LittleEndian.Uint16(c[22:]) != 32 ||
		binary.LittleEndian.Uint16(c[24:]) != 4 {
		return
	}
	x0 := int(int16(binary.LittleEndian.Uint16(c[8:]))) - int(int16(binary.LittleEndian.Uint16(c[16:])))
	y0 := int(int16(binary.LittleEndian.Uint16(c[10:]))) - int(int16(binary.LittleEndian.Uint16(c[18:])))
	for y := 0; y < 32; y++ {
		for x := 0; x < 32; x++ {
			px, py := x0+x, y0+y
			if !image.Pt(px, py).In(frame.Bounds()) {
				continue
			}
			bit := byte(0x80 >> (x & 7))
			at := y*4 + x/8
			and, xor := byte(0), byte(0)
			if c[28+at]&bit != 0 {
				and = 255
			}
			if c[156+at]&bit != 0 {
				xor = 255
			}
			pixel := frame.PixOffset(px, py)
			for component := 0; component < 3; component++ {
				frame.Pix[pixel+component] = frame.Pix[pixel+component]&and ^ xor
			}
		}
	}
}
