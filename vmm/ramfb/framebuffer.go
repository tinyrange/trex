// Package ramfb defines the TinyRangeX shared-memory display ABI.
package ramfb

import (
	"encoding/binary"
	"fmt"
	"image"
)

const (
	Address = 0xe0000000
	Size    = 8 << 20
	Pixels  = 4096
	Magic   = 0x31465254 // "TRF1", ABI version 1
)

// Header words: magic, active, width, height, stride, BGRX format (1).
// The host supplies magic; the driver publishes active last. Pixels are normal
// guest RAM. Capture must run while the guest CPU is stopped.
func Capture(memory []byte) (*image.RGBA, error) {
	if len(memory) < Pixels || binary.LittleEndian.Uint32(memory) != Magic || binary.LittleEndian.Uint32(memory[4:]) == 0 {
		return nil, nil
	}
	w := uint64(binary.LittleEndian.Uint32(memory[8:]))
	h := uint64(binary.LittleEndian.Uint32(memory[12:]))
	stride := uint64(binary.LittleEndian.Uint32(memory[16:]))
	if w == 0 || h == 0 || w > 1920 || h > 1080 || stride < w*4 || stride*h > uint64(len(memory)-Pixels) || binary.LittleEndian.Uint32(memory[20:]) != 1 {
		return nil, fmt.Errorf("invalid shared framebuffer layout")
	}
	out := image.NewRGBA(image.Rect(0, 0, int(w), int(h)))
	for y := uint64(0); y < h; y++ {
		src := memory[Pixels+y*stride : Pixels+y*stride+w*4]
		dst := out.Pix[int(y)*out.Stride:]
		for x := 0; x < len(src); x += 4 {
			dst[x], dst[x+1], dst[x+2], dst[x+3] = src[x+2], src[x+1], src[x], 255
		}
	}
	return out, nil
}
