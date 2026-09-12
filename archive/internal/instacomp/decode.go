package instacomp

import (
	"fmt"
	"io"
	"math/bits"
)

// InstaCompOne's codebooks and distance rules follow the reverse-engineering
// published by Maxim Poliakovski (ResDecompress) and Martin Michelsen
// (resource_dasm). See ../../macresource/LICENSE.compression for their MIT notices. This reader
// uses bounded output and a compact distance rule instead of per-range decoders.
type bitReader struct {
	data []byte
	pos  int64
	err  error
}

func (r *bitReader) read(n int) int {
	if r.err != nil {
		return 0
	}
	if n < 0 || n > 24 || int64(n) > int64(len(r.data))*8-r.pos {
		r.err = io.ErrUnexpectedEOF
		return 0
	}
	v := 0
	for i := 0; i < n; i++ {
		v = v<<1 | int(r.data[r.pos/8]>>uint(7-r.pos%8)&1)
		r.pos++
	}
	return v
}
func (r *bitReader) literalLength() int {
	if r.read(1) == 0 {
		return 1
	}
	switch r.read(2) {
	case 0:
		return 2
	case 1:
		return 3
	case 2:
		return 4 + r.read(2)
	default:
		if r.read(1) == 0 {
			return 8 + r.read(3)
		}
		if r.read(1) == 0 {
			return 16 + r.read(4)
		}
		return 32 + r.read(5)
	}
}
func (r *bitReader) copyLength() int {
	ones := 0
	for ones < 10 && r.read(1) != 0 {
		ones++
	}
	switch ones {
	case 0:
		return r.read(1)
	case 1:
		if r.read(1) == 0 {
			return 2
		}
		return 3 + r.read(1)
	case 2:
		if r.read(1) == 0 {
			return 5 + r.read(1)
		}
		return 7 + r.read(2)
	case 3:
		return 11 + r.read(3)
	case 4:
		return 19 + r.read(3)
	default:
		return (1 << uint(ones)) - 5 + r.read(ones)
	}
}
func (r *bitReader) distance(position int) int {
	return r.distanceMode(position, false, 0)
}

func (r *bitReader) copyLengthText() int {
	ones := 0
	for ones < 10 && r.read(1) != 0 {
		ones++
	}
	if ones < 3 {
		return 4*ones + r.read(2)
	}
	return (1 << uint(ones)) + 4 + r.read(ones)
}

func (r *bitReader) distanceMode(position int, ascii bool, historyLimit int) int {
	// The first two ranges have fixed widths. The third range width depends
	// on bytes already decoded. Threshold irregularities are part of the
	// original codec, not opportunities to substitute a generic LZ decoder.
	thresholds := [...]int{10, 20, 40, 80, 160, 672, 1000, 2688, 5376, 10752, 21504, 43008, 70000, 172032, 344064}
	if ascii {
		thresholds = [...]int{10, 20, 40, 80, 160, 320, 832, 1280, 2560, 5120, 10240, 30000, 50000, 172032, 344064}
	}
	k := 0
	for k < len(thresholds)-1 && position > thresholds[k] {
		// The text dispatcher also stops increasing the codebook at the
		// configured window size (e.g. 32768 for the 30000 threshold).
		if ascii && k >= 7 && historyLimit > 0 && historyLimit <= 1<<uint(k+4) {
			break
		}
		k++
	}
	if position <= 0 || position > thresholds[len(thresholds)-1] {
		r.err = fmt.Errorf("unsupported dcmp3 history size %d", position)
		return 0
	}
	if r.read(1) == 0 {
		return 1 + r.read(k)
	}
	if r.read(1) == 0 {
		return (1 << uint(k)) + 1 + r.read(k+2)
	}
	base := 5 << uint(k)
	width := bits.Len(uint(max(1, position-base) - 1))
	if width == 0 {
		width = 1
	}
	// Preserve documented irregularities in the original decoder's ranges.
	if k == 7 && position > 0x66c && position <= 0x680 {
		width = 11
	}
	return base + 1 + r.read(width)
}

// Decode appends complete commands until output reaches target. limit is a hard
// output bound; allowing limit > target lets a Tome block end after a command
// crossing its nominal block size. historyLimit zero selects unbounded resource
// history; a nonzero value restricts both distance coding and references.
// The returned byte count includes the final partially consumed byte.
func Decode(input, output []byte, target, limit, historyLimit int) ([]byte, int, error) {
	return decode(input, output, target, limit, historyLimit, false)
}

// DecodeASCII decodes Tome's seven-bit text variant with its 32KiB window.
// Length and distance dispatch rules were inspected directly in the original
// Mac7.5 installer exfn/241, then verified against every text fork checksum.
func DecodeASCII(input, output []byte, target, limit int) ([]byte, int, error) {
	return decode(input, output, target, limit, 32768, true)
}

func decode(input, output []byte, target, limit, historyLimit int, ascii bool) ([]byte, int, error) {
	if target < len(output) || limit < target || historyLimit < 0 {
		return nil, 0, fmt.Errorf("invalid InstaCompOne limits")
	}
	r := bitReader{data: input}
	literalsAllowed := true
	for len(output) < target {
		var n int
		if ascii {
			n = r.copyLengthText()
		} else {
			n = r.copyLength()
		}
		if n == 0 && literalsAllowed {
			n = r.literalLength()
			literalsAllowed = n == 63
			if n > limit-len(output) {
				return nil, 0, fmt.Errorf("literal exceeds declared size")
			}
			for i := 0; i < n; i++ {
				width := 8
				if ascii {
					width = 7
				}
				value := r.read(width)
				if r.err != nil {
					return nil, 0, r.err
				}
				output = append(output, byte(value))
			}
		} else {
			n += 2
			if !literalsAllowed {
				n++
			}
			literalsAllowed = true
			history := len(output)
			if historyLimit != 0 {
				history = min(history, historyLimit)
			}
			distance := r.distanceMode(history, ascii, historyLimit)
			if r.err != nil {
				return nil, 0, r.err
			}
			if distance <= 0 || distance > history || n > limit-len(output) {
				return nil, 0, fmt.Errorf("invalid backreference at %d: distance %d length %d", len(output), distance, n)
			}
			for i := 0; i < n; i++ {
				output = append(output, output[len(output)-distance])
			}
		}
	}
	return output, int((r.pos + 7) / 8), r.err
}
