package upx

import (
	"fmt"
	"io"
)

// NRV2B_8 interleaves literal and distance bytes with groups of eight
// control bits. The controls are consumed most significant bit first.
type nrvInput struct {
	remaining []byte
	control   byte
	mask      byte
	truncated bool
}

func (in *nrvInput) byte() byte {
	if len(in.remaining) == 0 {
		in.truncated = true
		return 0
	}
	b := in.remaining[0]
	in.remaining = in.remaining[1:]
	return b
}

func (in *nrvInput) bit() int {
	if in.mask == 0 {
		in.control, in.mask = in.byte(), 0x80
	}
	b := in.control & in.mask
	in.mask >>= 1
	if b != 0 {
		return 1
	}
	return 0
}

// A prefix alternates a value bit with a stop bit, with an implicit leading 1.
func (in *nrvInput) prefix(maximum int) (int, error) {
	value := 1
	for {
		value = 2*value + in.bit()
		last := in.bit() == 1
		if in.truncated {
			return 0, io.ErrUnexpectedEOF
		}
		if value > maximum {
			return 0, fmt.Errorf("NRV2B prefix exceeds its bound")
		}
		if last {
			return value, nil
		}
	}
}

func decodeNRV2B8(payload []byte, imageSize int) ([]byte, error) {
	in := nrvInput{remaining: payload}
	image := make([]byte, 0, imageSize)
	var distance uint32 = 1
	for {
		if in.bit() == 1 {
			literal := in.byte()
			if in.truncated {
				return nil, io.ErrUnexpectedEOF
			}
			if len(image) == imageSize {
				return nil, fmt.Errorf("NRV2B literal exceeds image size")
			}
			image = append(image, literal)
			continue
		}
		code, err := in.prefix(0x1000002)
		if err != nil {
			return nil, err
		}
		if code != 2 {
			offset := uint32(code-3)<<8 | uint32(in.byte())
			if in.truncated {
				return nil, io.ErrUnexpectedEOF
			}
			if offset == 0xffffffff {
				if len(image) != imageSize || len(in.remaining) != 0 {
					return nil, fmt.Errorf("NRV2B end marker does not match declared sizes")
				}
				return image, nil
			}
			distance = offset + 1
		}
		length := 2*in.bit() + in.bit()
		if length == 0 {
			extended, err := in.prefix(imageSize - len(image))
			if err != nil {
				return nil, err
			}
			length = extended + 2
		}
		length++
		if distance > 0xd00 {
			length++
		}
		if in.truncated {
			return nil, io.ErrUnexpectedEOF
		}
		if distance > uint32(len(image)) || length > imageSize-len(image) {
			return nil, fmt.Errorf("NRV2B match outside image")
		}
		for range length {
			image = append(image, image[len(image)-int(distance)])
		}
	}
}
