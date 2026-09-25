package nsis

// This decoder is original project code. It implements DEFLATE's canonical
// Huffman representation and NSIS's stored-block layout (LEN without NLEN).
// No NSIS, 7-Zip or third-party decoder implementation is incorporated.

import (
	"fmt"
	"io"
)

type bitInput struct {
	data  []byte
	at    int
	bits  uint64
	count uint
}

func (b *bitInput) take(n uint) (uint32, error) {
	for b.count < n {
		if b.at >= len(b.data) {
			return 0, io.ErrUnexpectedEOF
		}
		b.bits |= uint64(b.data[b.at]) << b.count
		b.at++
		b.count += 8
	}
	v := uint32(b.bits & ((1 << n) - 1))
	b.bits >>= n
	b.count -= n
	return v, nil
}

type huffman struct {
	first   [16]int
	count   [16]int
	start   [16]int
	symbols []int
}

func makeHuffman(lengths []int) (huffman, error) {
	h := huffman{}
	for _, n := range lengths {
		if n < 0 || n > 15 {
			return h, fmt.Errorf("nsis deflate: invalid code length")
		}
		if n != 0 {
			h.count[n]++
		}
	}
	total, code := 0, 0
	for n := 1; n <= 15; n++ {
		code = (code + h.count[n-1]) << 1
		h.first[n], h.start[n] = code, total
		if code+h.count[n] > 1<<n {
			return h, fmt.Errorf("nsis deflate: oversubscribed code tree")
		}
		total += h.count[n]
	}
	h.symbols = make([]int, total)
	cursor := h.start
	for sym, n := range lengths {
		if n > 0 {
			h.symbols[cursor[n]] = sym
			cursor[n]++
		}
	}
	return h, nil
}
func (h *huffman) read(b *bitInput) (int, error) {
	code := 0
	for n := 1; n <= 15; n++ {
		v, err := b.take(1)
		if err != nil {
			return 0, err
		}
		code = code<<1 | int(v)
		d := code - h.first[n]
		if d >= 0 && d < h.count[n] {
			return h.symbols[h.start[n]+d], nil
		}
	}
	return 0, fmt.Errorf("nsis deflate: invalid Huffman code")
}

func deflateTrees(b *bitInput, fixed bool) (huffman, huffman, error) {
	if fixed {
		ll := make([]int, 288)
		for i := range ll {
			switch {
			case i < 144:
				ll[i] = 8
			case i < 256:
				ll[i] = 9
			case i < 280:
				ll[i] = 7
			default:
				ll[i] = 8
			}
		}
		dd := make([]int, 32)
		for i := range dd {
			dd[i] = 5
		}
		l, _ := makeHuffman(ll)
		d, _ := makeHuffman(dd)
		return l, d, nil
	}
	empty := huffman{}
	a, err := b.take(5)
	if err != nil {
		return empty, empty, err
	}
	c, err := b.take(5)
	if err != nil {
		return empty, empty, err
	}
	e, err := b.take(4)
	if err != nil {
		return empty, empty, err
	}
	nl, nd, nc := int(a)+257, int(c)+1, int(e)+4
	if nl > 286 {
		return empty, empty, fmt.Errorf("nsis deflate: too many literal codes")
	}
	// Code-length alphabet order from the DEFLATE wire format.
	order := []int{16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15}
	cl := make([]int, 19)
	for i := 0; i < nc; i++ {
		v, err := b.take(3)
		if err != nil {
			return empty, empty, err
		}
		cl[order[i]] = int(v)
	}
	tree, err := makeHuffman(cl)
	if err != nil {
		return empty, empty, err
	}
	lengths := make([]int, 0, nl+nd)
	for len(lengths) < nl+nd {
		sym, err := tree.read(b)
		if err != nil {
			return empty, empty, err
		}
		if sym < 16 {
			lengths = append(lengths, sym)
			continue
		}
		value, extra, base := 0, uint(0), 0
		switch sym {
		case 16:
			if len(lengths) == 0 {
				return empty, empty, fmt.Errorf("nsis deflate: repeat without previous length")
			}
			value, extra, base = lengths[len(lengths)-1], 2, 3
		case 17:
			extra, base = 3, 3
		case 18:
			extra, base = 7, 11
		default:
			return empty, empty, fmt.Errorf("nsis deflate: invalid length symbol")
		}
		v, err := b.take(extra)
		if err != nil {
			return empty, empty, err
		}
		n := int(v) + base
		if n > nl+nd-len(lengths) {
			return empty, empty, fmt.Errorf("nsis deflate: code length repeat overflow")
		}
		for j := 0; j < n; j++ {
			lengths = append(lengths, value)
		}
	}
	if lengths[256] == 0 {
		return empty, empty, fmt.Errorf("nsis deflate: missing end code")
	}
	l, err := makeHuffman(lengths[:nl])
	if err != nil {
		return empty, empty, err
	}
	d, err := makeHuffman(lengths[nl:])
	return l, d, err
}

func inflateNSIS(data []byte, maximum int64) ([]byte, error) {
	if maximum < 0 {
		return nil, ErrLimit
	}
	b := bitInput{data: data}
	out := make([]byte, 0, min(int64(32768), maximum))
	lengthBase := []int{3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258}
	lengthBits := []uint{0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0}
	distanceBase := []int{1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577}
	distanceBits := []uint{0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13}
	for {
		final, err := b.take(1)
		if err != nil {
			return nil, err
		}
		kind, err := b.take(2)
		if err != nil {
			return nil, err
		}
		if kind == 0 {
			b.bits, b.count = 0, 0
			size, err := b.take(16)
			if err != nil {
				return nil, err
			}
			n := int(size)
			if n > len(data)-b.at {
				return nil, io.ErrUnexpectedEOF
			}
			if int64(n) > maximum-int64(len(out)) {
				return nil, ErrLimit
			}
			out = append(out, data[b.at:b.at+n]...)
			b.at += n
		} else if kind < 3 {
			literal, distance, err := deflateTrees(&b, kind == 1)
			if err != nil {
				return nil, err
			}
			for {
				sym, err := literal.read(&b)
				if err != nil {
					return nil, err
				}
				if sym == 256 {
					break
				}
				if sym < 256 {
					if int64(len(out)) >= maximum {
						return nil, ErrLimit
					}
					out = append(out, byte(sym))
					continue
				}
				if sym > 285 {
					return nil, fmt.Errorf("nsis deflate: reserved length")
				}
				index := sym - 257
				v, err := b.take(lengthBits[index])
				if err != nil {
					return nil, err
				}
				n := lengthBase[index] + int(v)
				ds, err := distance.read(&b)
				if err != nil {
					return nil, err
				}
				if ds >= 30 {
					return nil, fmt.Errorf("nsis deflate: reserved distance")
				}
				v, err = b.take(distanceBits[ds])
				if err != nil {
					return nil, err
				}
				back := distanceBase[ds] + int(v)
				if back > len(out) {
					return nil, fmt.Errorf("nsis deflate: distance before output")
				}
				if int64(n) > maximum-int64(len(out)) {
					return nil, ErrLimit
				}
				for j := 0; j < n; j++ {
					out = append(out, out[len(out)-back])
				}
			}
		} else {
			return nil, fmt.Errorf("nsis deflate: reserved block type")
		}
		if final != 0 {
			break
		}
	}
	if b.at != len(data) {
		return nil, fmt.Errorf("nsis deflate: trailing compressed bytes (%d)", len(data)-b.at)
	}
	return out, nil
}
