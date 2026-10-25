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

// Header words: magic, active, width, height, stride, pixel format.
// Format 1 is BGRX; format 2 is monochrome, most-significant bit first,
// with zero black and one white. Each row starts at its declared stride.
// The host supplies magic; the driver publishes active last. Pixels are normal
// guest RAM. Capture must run while the guest CPU is stopped.
func Capture(memory []byte) (*image.RGBA, error) {
	if len(memory) < Pixels || binary.LittleEndian.Uint32(memory) != Magic || binary.LittleEndian.Uint32(memory[4:]) == 0 {
		return nil, nil
	}
	w := uint64(binary.LittleEndian.Uint32(memory[8:]))
	h := uint64(binary.LittleEndian.Uint32(memory[12:]))
	stride := uint64(binary.LittleEndian.Uint32(memory[16:]))
	format := binary.LittleEndian.Uint32(memory[20:])
	if !validPixelLayout(w, h, stride, format, len(memory)-Pixels) {
		return nil, fmt.Errorf("invalid shared framebuffer layout")
	}
	out := image.NewRGBA(image.Rect(0, 0, int(w), int(h)))
	for y := uint64(0); y < h; y++ {
		if format == 2 {
			src := memory[Pixels+y*stride : Pixels+y*stride+(w+7)/8]
			dst := out.Pix[int(y)*out.Stride:]
			for x := uint64(0); x < w; x++ {
				var value byte
				if src[x/8]&(0x80>>(x%8)) != 0 {
					value = 255
				}
				dst[x*4], dst[x*4+1], dst[x*4+2], dst[x*4+3] = value, value, value, 255
			}
			continue
		}
		src := memory[Pixels+y*stride : Pixels+y*stride+w*4]
		dst := out.Pix[int(y)*out.Stride:]
		for x := 0; x < len(src); x += 4 {
			dst[x], dst[x+1], dst[x+2], dst[x+3] = src[x+2], src[x+1], src[x], 255
		}
	}
	compositeCursor(out, memory)
	return out, nil
}

func validPixelLayout(w, h, stride uint64, format uint32, available int) bool {
	minimum := w * 4
	if format == 2 {
		minimum = (w + 7) / 8
	} else if format != 1 {
		return false
	}
	return w != 0 && h != 0 && w <= MaxWidth && h <= MaxHeight && stride >= minimum && stride*h <= uint64(available)
}
