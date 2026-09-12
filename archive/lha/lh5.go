package lha

import "fmt"

// LH5 uses MSB-first canonical Huffman tables and an 8KiB LZ window.
// Format facts were checked against libarchive's BSD-licensed LHA reader;
// this bounded byte-slice implementation does not use its state machine.
type bits struct {
	data []byte
	pos  int
	err  error
}

func (b *bits) read(n int) int {
	if b.err != nil {
		return 0
	}
	if n < 0 || n > 24 || n > len(b.data)*8-b.pos {
		b.err = fmt.Errorf("lha: truncated bits")
		return 0
	}
	v := 0
	for i := 0; i < n; i++ {
		v = v<<1 | int((b.data[b.pos/8]>>uint(7-b.pos%8))&1)
		b.pos++
	}
	return v
}

type key struct{ width, code int }
type tree struct {
	single int
	codes  map[key]int
}

func canonical(lengths []int) (tree, error) {
	t := tree{single: -1, codes: map[key]int{}}
	var counts [17]int
	for _, n := range lengths {
		if n < 0 || n > 16 {
			return t, fmt.Errorf("lha: invalid Huffman length")
		}
		counts[n]++
	}
	code := 0
	for width := 1; width <= 16; width++ {
		if width > 1 {
			code = (code + counts[width-1]) << 1
		}
		if code+counts[width] > 1<<width {
			return t, fmt.Errorf("lha: oversubscribed Huffman tree")
		}
		next := code
		for value, n := range lengths {
			if n == width {
				t.codes[key{width, next}] = value
				next++
			}
		}
	}
	if code+counts[16] != 1<<16 {
		return t, fmt.Errorf("lha: incomplete Huffman tree")
	}
	return t, nil
}
func (t tree) symbol(b *bits) int {
	if t.single >= 0 {
		return t.single
	}
	code := 0
	for n := 1; n <= 16; n++ {
		code = code<<1 | b.read(1)
		if b.err != nil {
			return 0
		}
		if v, ok := t.codes[key{n, code}]; ok {
			return v
		}
	}
	b.err = fmt.Errorf("lha: invalid Huffman code")
	return 0
}
func lengthsTree(b *bits, size, width int, special bool) tree {
	n := b.read(width)
	if n == 0 {
		v := b.read(width)
		if v >= size {
			b.err = fmt.Errorf("lha: constant symbol outside alphabet")
		}
		return tree{single: v}
	}
	if n > size {
		b.err = fmt.Errorf("lha: too many code lengths")
		return tree{}
	}
	lengths := make([]int, size)
	for i := 0; i < n && b.err == nil; {
		v := b.read(3)
		if v == 7 {
			for b.read(1) != 0 && b.err == nil {
				v++
				if v > 16 {
					b.err = fmt.Errorf("lha: code length exceeds 16")
					break
				}
			}
		}
		lengths[i] = v
		i++
		if special && i == 3 {
			skip := b.read(2)
			if skip > n-i {
				b.err = fmt.Errorf("lha: code-length gap exceeds table")
				break
			}
			i += skip
		}
	}
	if b.err != nil {
		return tree{}
	}
	t, err := canonical(lengths)
	b.err = err
	return t
}
func literalTree(b *bits, prefix tree) tree {
	n := b.read(9)
	if n == 0 {
		v := b.read(9)
		if v >= 510 {
			b.err = fmt.Errorf("lha: invalid constant literal")
		}
		return tree{single: v}
	}
	if n > 510 {
		b.err = fmt.Errorf("lha: literal alphabet too large")
		return tree{}
	}
	lengths := make([]int, 510)
	for i := 0; i < n && b.err == nil; {
		v := prefix.symbol(b)
		if v >= 3 {
			lengths[i] = v - 2
			i++
			continue
		}
		run := 1
		if v == 1 {
			run = b.read(4) + 3
		} else if v == 2 {
			run = b.read(9) + 20
		}
		if run > n-i {
			b.err = fmt.Errorf("lha: literal zero run exceeds table")
			break
		}
		i += run
	}
	if b.err != nil {
		return tree{}
	}
	t, err := canonical(lengths)
	b.err = err
	return t
}
func decodeLH5(input []byte, size int) ([]byte, error) {
	if size < 0 {
		return nil, fmt.Errorf("lha: negative decoded size")
	}
	b := bits{data: input}
	out := make([]byte, 0, size)
	var window [8192]byte
	for i := range window {
		window[i] = ' '
	}
	position := 0
	for len(out) < size {
		count := b.read(16)
		if b.err != nil {
			return nil, b.err
		}
		if count == 0 {
			return nil, fmt.Errorf("lha: empty compressed block")
		}
		prefix := lengthsTree(&b, 19, 5, true)
		literal := literalTree(&b, prefix)
		distance := lengthsTree(&b, 14, 4, false)
		if b.err != nil {
			return nil, b.err
		}
		for i := 0; i < count; i++ {
			v := literal.symbol(&b)
			if b.err != nil {
				return nil, b.err
			}
			length, back := 1, 0
			if v >= 256 {
				length = v - 253
				d := distance.symbol(&b)
				if d > 0 {
					back = (1 << (d - 1)) + b.read(d-1)
				}
				back++
			}
			if b.err != nil {
				return nil, b.err
			}
			if length > size-len(out) {
				return nil, fmt.Errorf("lha: block exceeds decoded size")
			}
			for j := 0; j < length; j++ {
				value := byte(v)
				if back != 0 {
					value = window[(position-back+8192)%8192]
				}
				out = append(out, value)
				window[position] = value
				position = (position + 1) % 8192
			}
		}
	}
	// Up to one zero byte is emitted by some historical bit flushers.
	if len(input)*8-b.pos > 15 {
		return nil, fmt.Errorf("lha: excess compressed payload")
	}
	for b.pos < len(input)*8 {
		if b.read(1) != 0 {
			return nil, fmt.Errorf("lha: nonzero compressed padding")
		}
	}
	return out, b.err
}
