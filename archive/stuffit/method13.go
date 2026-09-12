package stuffit

import (
	"fmt"
	"io"
)

type bitReader struct {
	data []byte
	pos  int64
}

func (r *bitReader) read(n int) (uint32, error) {
	if n < 0 || n > 32 || int64(n) > int64(len(r.data))*8-r.pos {
		return 0, io.ErrUnexpectedEOF
	}
	var v uint32
	for i := 0; i < n; i++ {
		v |= uint32(r.data[r.pos/8]>>uint(r.pos%8)&1) << uint(i)
		r.pos++
	}
	return v, nil
}

type huffman13 struct{ codes [33]map[uint32]int }

func makeCode13(lengths []int) (huffman13, error) {
	var h huffman13
	for _, n := range lengths {
		if n < -1 || n > 32 {
			return h, fmt.Errorf("invalid code length %d", n)
		}
	}
	var code uint64
	for width := 1; width <= 32; width++ {
		for symbol, length := range lengths {
			if length != width {
				continue
			}
			step := uint64(1) << uint(32-width)
			if code+step > uint64(1)<<32 {
				return h, fmt.Errorf("oversubscribed Huffman table")
			}
			if h.codes[width] == nil {
				h.codes[width] = map[uint32]int{}
			}
			h.codes[width][uint32(code>>uint(32-width))] = symbol
			code += step
		}
	}
	return h, nil
}
func (h *huffman13) read(r *bitReader) (int, error) {
	var code uint32
	for width := 1; width <= 32; width++ {
		b, err := r.read(1)
		if err != nil {
			return 0, err
		}
		code = code<<1 | b
		if symbol, ok := h.codes[width][code]; ok {
			return symbol, nil
		}
	}
	return 0, fmt.Errorf("invalid Huffman code")
}
func meta13(r *bitReader) (int, error) {
	var code uint32
	for width := 1; width <= 12; width++ {
		b, err := r.read(1)
		if err != nil {
			return 0, err
		}
		code |= b << uint(width-1)
		for i, n := range metaCodeLengths {
			if n == width && uint32(metaCodes[i]) == code {
				return i, nil
			}
		}
	}
	return 0, fmt.Errorf("invalid Huffman meta-code")
}
func readLengths13(r *bitReader, count int) ([]int, error) {
	lengths := make([]int, 0, count)
	length := 0
	for len(lengths) < count {
		symbol, err := meta13(r)
		if err != nil {
			return nil, err
		}
		repeat := 1
		switch {
		case symbol < 31:
			length = symbol + 1
		case symbol == 31:
			length = -1
		case symbol == 32:
			length++
		case symbol == 33:
			length--
		default:
			width, base := 1, 0
			if symbol == 35 {
				width, base = 3, 2
			} else if symbol == 36 {
				width, base = 6, 10
			}
			v, err := r.read(width)
			if err != nil {
				return nil, err
			}
			repeat += int(v) + base
		}
		if length < -1 || length > 32 || repeat > count-len(lengths) {
			return nil, fmt.Errorf("invalid code-length run")
		}
		for i := 0; i < repeat; i++ {
			lengths = append(lengths, length)
		}
	}
	return lengths, nil
}
func decode13(input []byte, size int) ([]byte, error) {
	if len(input) == 0 {
		return nil, io.ErrUnexpectedEOF
	}
	r := bitReader{data: input, pos: 8}
	selector := input[0] >> 4
	var lengths [3][]int
	if selector == 0 {
		var err error
		lengths[0], err = readLengths13(&r, 321)
		if err != nil {
			return nil, err
		}
		if input[0]&8 != 0 {
			lengths[1] = lengths[0]
		} else {
			lengths[1], err = readLengths13(&r, 321)
			if err != nil {
				return nil, err
			}
		}
		lengths[2], err = readLengths13(&r, int(input[0]&7)+10)
		if err != nil {
			return nil, err
		}
	} else if selector <= 5 {
		lengths = predefined13[selector-1]
	} else {
		return nil, fmt.Errorf("unknown method13 table selector %d", selector)
	}
	var tables [3]huffman13
	for i, l := range lengths {
		var err error
		tables[i], err = makeCode13(l)
		if err != nil {
			return nil, err
		}
	}
	var history [65536]byte
	output := make([]byte, 0, min(size, 1<<20))
	current := 0
	for {
		symbol, err := tables[current].read(&r)
		if err != nil {
			return nil, err
		}
		if symbol == 320 {
			if len(output) != size {
				return nil, fmt.Errorf("decoded length %d, expected %d", len(output), size)
			}
			// Original StuffIt encoders flush their bit buffer in 32-bit
			// units following the one-byte selector. Also accept a minimally
			// byte-padded stream; no other trailing data is permitted.
			end, aligned := (r.pos+7)/8, 1+(r.pos-8+31)/32*4
			if int64(len(input)) != end && int64(len(input)) != aligned {
				return nil, fmt.Errorf("trailing method13 bytes")
			}
			for r.pos < int64(len(input))*8 {
				v, err := r.read(1)
				if err != nil {
					return nil, err
				}
				if v != 0 {
					return nil, fmt.Errorf("nonzero method13 padding")
				}
			}
			return output, nil
		}
		if symbol < 256 {
			if len(output) == size {
				return nil, fmt.Errorf("literal exceeds declared size")
			}
			history[len(output)&65535] = byte(symbol)
			output = append(output, byte(symbol))
			current = 0
			continue
		}
		n := symbol - 253
		if symbol == 318 || symbol == 319 {
			width := 10
			if symbol == 319 {
				width = 15
			}
			v, err := r.read(width)
			if err != nil {
				return nil, err
			}
			n = int(v) + 65
		}
		width, err := tables[2].read(&r)
		if err != nil {
			return nil, err
		}
		distance := 1
		if width > 0 {
			v, err := r.read(width - 1)
			if err != nil {
				return nil, err
			}
			distance += 1<<uint(width-1) | int(v)
		}
		if distance > 65536 || n > size-len(output) {
			return nil, fmt.Errorf("match exceeds window or declared output")
		}
		for i := 0; i < n; i++ {
			v := history[(len(output)-distance)&65535]
			history[len(output)&65535] = v
			output = append(output, v)
		}
		current = 1
	}
}
