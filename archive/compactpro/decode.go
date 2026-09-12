// Package compactpro reads CompactPro catalogs and separate Macintosh forks.
// Format facts: theunarchiver's CompactProSpecs, CompactProLzhAlgorithm and
// Rle8182Algorithm wiki documents. No external decoder or guest code is used.
package compactpro

import (
	"fmt"
	"io"
)

type bitReader struct {
	data []byte
	bit  int64
}

func (r *bitReader) read(n int) (int, error) {
	if n < 0 || n > 16 || int64(n) > int64(len(r.data))*8-r.bit {
		return 0, io.ErrUnexpectedEOF
	}
	v := 0
	for i := 0; i < n; i++ {
		v = v<<1 | int(r.data[r.bit/8]>>uint(7-r.bit%8)&1)
		r.bit++
	}
	return v, nil
}

type codebook struct{ values [16]map[int]int }

func readCodebook(r *bitReader, maximum int) (codebook, error) {
	var c codebook
	n, err := r.read(8)
	if err != nil {
		return c, err
	}
	if n*2 > maximum {
		return c, fmt.Errorf("codebook exceeds alphabet")
	}
	lengths := make([]int, n*2)
	for i := range lengths {
		lengths[i], err = r.read(4)
		if err != nil {
			return c, err
		}
	}
	code := 0
	for width := 1; width <= 15; width++ {
		for symbol, length := range lengths {
			if length != width {
				continue
			}
			if code+(1<<uint(16-width)) > 65536 {
				return c, fmt.Errorf("oversubscribed codebook")
			}
			if c.values[width] == nil {
				c.values[width] = map[int]int{}
			}
			c.values[width][code>>uint(16-width)] = symbol
			code += 1 << uint(16-width)
		}
	}
	return c, nil
}
func (c *codebook) symbol(r *bitReader) (int, error) {
	v := 0
	for width := 1; width <= 15; width++ {
		b, err := r.read(1)
		if err != nil {
			return 0, err
		}
		v = v<<1 | b
		if symbol, ok := c.values[width][v]; ok {
			return symbol, nil
		}
	}
	return 0, fmt.Errorf("invalid Huffman code")
}

type rleDecoder struct {
	output  []byte
	limit   int
	pending int
}

func (r *rleDecoder) emit(v byte, n int) error {
	if n < 0 || n > r.limit-len(r.output) {
		return fmt.Errorf("RLE output exceeds declared size")
	}
	for i := 0; i < n; i++ {
		r.output = append(r.output, v)
	}
	return nil
}
func (r *rleDecoder) feed(v byte) error {
	switch r.pending {
	case 2:
		r.pending = 0
		if v == 0 {
			if err := r.emit(0x81, 1); err != nil {
				return err
			}
			return r.emit(0x82, 1)
		}
		if len(r.output) == 0 {
			return fmt.Errorf("RLE repetition before first byte")
		}
		return r.emit(r.output[len(r.output)-1], int(v)-1)
	case 1:
		if v == 0x82 {
			r.pending = 2
			return nil
		}
		if err := r.emit(0x81, 1); err != nil {
			return err
		}
		r.pending = 0
	}
	if v == 0x81 {
		r.pending = 1
		return nil
	}
	return r.emit(v, 1)
}
func (r *rleDecoder) finish() error {
	if r.pending == 1 {
		if err := r.emit(0x81, 1); err != nil {
			return err
		}
		r.pending = 0
	}
	if r.pending != 0 || len(r.output) != r.limit {
		return fmt.Errorf("RLE truncated: decoded %d, expected %d", len(r.output), r.limit)
	}
	return nil
}

func decode(input []byte, size int, lzh bool) ([]byte, error) {
	out := rleDecoder{limit: size}
	if !lzh {
		for _, b := range input {
			if err := out.feed(b); err != nil {
				return nil, err
			}
		}
		if err := out.finish(); err != nil {
			return nil, err
		}
		return out.output, nil
	}
	if size == 0 {
		if len(input) != 0 {
			return nil, fmt.Errorf("nonempty compressed zero-size fork")
		}
		return []byte{}, nil
	}
	r := bitReader{data: input}
	var history [8192]byte
	position := int64(0)
	for len(out.output) < size {
		literal, err := readCodebook(&r, 256)
		if err != nil {
			return nil, err
		}
		length, err := readCodebook(&r, 64)
		if err != nil {
			return nil, err
		}
		distance, err := readCodebook(&r, 128)
		if err != nil {
			return nil, err
		}
		start := r.bit / 8
		for symbols := 0; symbols < 0x1fff0 && len(out.output) < size; {
			flag, err := r.read(1)
			if err != nil {
				return nil, err
			}
			var data []byte
			if flag == 1 {
				v, err := literal.symbol(&r)
				if err != nil {
					return nil, err
				}
				data = []byte{byte(v)}
				symbols += 2
			} else {
				n, err := length.symbol(&r)
				if err != nil {
					return nil, err
				}
				hi, err := distance.symbol(&r)
				if err != nil {
					return nil, err
				}
				lo, err := r.read(6)
				if err != nil {
					return nil, err
				}
				dist := int64(hi<<6 | lo)
				if n == 0 {
					return nil, fmt.Errorf("invalid LZH match length %d distance %d at %d", n, dist, position)
				}
				// A zero offset addresses the current ring slot (8192 bytes
				// back), not the byte being appended. The initial 8KiB window
				// is zero-filled, including references
				// preceding the first output byte. Feed overlapping matches one
				// byte at a time, retaining only the
				// LZH history (the following RLE stage has a different history).
				for i := 0; i < n; i++ {
					v := history[(position-dist)&8191]
					history[position&8191] = v
					position++
					if err := out.feed(v); err != nil {
						return nil, err
					}
				}
				symbols += 3
			}
			for _, v := range data {
				history[position&8191] = v
				position++
				if err := out.feed(v); err != nil {
					return nil, err
				}
			}
			// A terminal literal 0x81 needs no following escape byte. Only
			// recognize it when the rest is exactly the codec's final padding.
			if out.pending == 1 && len(out.output)+1 == size && paddedEnd(r.bit, start) == int64(len(input)) {
				if err := out.finish(); err != nil {
					return nil, err
				}
			}
		}
		end := paddedEnd(r.bit, start)
		if end > int64(len(input)) {
			return nil, io.ErrUnexpectedEOF
		}
		r.bit = end * 8
	}
	if err := out.finish(); err != nil {
		return nil, err
	}
	if r.bit != int64(len(input))*8 {
		return nil, fmt.Errorf("trailing compressed bytes")
	}
	return out.output, nil
}
func paddedEnd(bit, start int64) int64 { end := (bit + 7) / 8; return end + 2 + (end-start)%2 }
