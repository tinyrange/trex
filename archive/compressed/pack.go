package compressed

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"github.com/tinyrange/trex/storage"
	"io"
)

// packReader reads the 1f1e UNIX pack format. Its canonical Huffman codes are
// allocated from the deepest level upwards, unlike common shortest-first
// conventions. The final depth's stored leaf count omits two leaves: one
// ordinary symbol and the implicit end symbol. Verified against IRIX media.
type packReader struct {
	input                 *bufio.Reader
	counts, bases, starts [25]uint32
	symbols               []byte
	levels                int
	expected, produced    uint32
	current               byte
	bits                  uint
	done                  bool
}

func newPackReader(source storage.Reader) (io.Reader, error) {
	r := &packReader{input: bufio.NewReader(io.NewSectionReader(source, 0, source.Size()))}
	var h [7]byte
	if _, err := io.ReadFull(r.input, h[:]); err != nil {
		return nil, err
	}
	if h[0] != 0x1f || h[1] != 0x1e {
		return nil, fmt.Errorf("pack: invalid magic")
	}
	r.expected = binary.BigEndian.Uint32(h[2:6])
	r.levels = int(h[6])
	if r.levels < 1 || r.levels > 24 {
		return nil, fmt.Errorf("pack: unsupported depth %d", r.levels)
	}
	var total uint32
	for depth := 1; depth <= r.levels; depth++ {
		b, err := r.input.ReadByte()
		if err != nil {
			return nil, err
		}
		r.counts[depth] = uint32(b)
		if depth == r.levels {
			r.counts[depth] += 2
		}
		r.starts[depth] = total
		total += r.counts[depth]
	}
	if total > 257 {
		return nil, fmt.Errorf("pack: too many leaves")
	}
	for depth := r.levels - 1; depth > 0; depth-- {
		below := r.bases[depth+1] + r.counts[depth+1]
		if below&1 != 0 {
			return nil, fmt.Errorf("pack: incomplete prefix tree")
		}
		r.bases[depth] = below / 2
	}
	if r.bases[1]+r.counts[1] != 2 {
		return nil, fmt.Errorf("pack: invalid prefix tree")
	}
	r.symbols = make([]byte, total-1)
	if _, err := io.ReadFull(r.input, r.symbols); err != nil {
		return nil, err
	}
	var seen [256]bool
	for _, symbol := range r.symbols {
		if seen[symbol] {
			return nil, fmt.Errorf("pack: duplicate symbol")
		}
		seen[symbol] = true
	}
	return r, nil
}

func (r *packReader) Read(p []byte) (int, error) {
	n := 0
	for len(p) > 0 {
		if r.done {
			return n, io.EOF
		}
		var code uint32
		found := false
		for depth := 1; depth <= r.levels; depth++ {
			if r.bits == 0 {
				b, err := r.input.ReadByte()
				if err != nil {
					if err == io.EOF {
						err = io.ErrUnexpectedEOF
					}
					return n, err
				}
				r.current = b
				r.bits = 8
			}
			r.bits--
			code = code<<1 | uint32(r.current>>r.bits&1)
			if code < r.bases[depth] || code-r.bases[depth] >= r.counts[depth] {
				continue
			}
			index := r.starts[depth] + code - r.bases[depth]
			if index == uint32(len(r.symbols)) {
				if r.produced != r.expected {
					return n, fmt.Errorf("pack: decoded %d bytes, expected %d", r.produced, r.expected)
				}
				if r.current&byte((1<<r.bits)-1) != 0 {
					return n, fmt.Errorf("pack: nonzero end padding")
				}
				if _, err := r.input.ReadByte(); err != io.EOF {
					return n, fmt.Errorf("pack: trailing data or read error: %v", err)
				}
				r.done = true
				return n, io.EOF
			}
			if r.produced >= r.expected {
				return n, fmt.Errorf("pack: decoded data exceeds declared size")
			}
			p[0] = r.symbols[index]
			p = p[1:]
			n++
			r.produced++
			found = true
			break
		}
		if !found {
			return n, fmt.Errorf("pack: invalid code")
		}
	}
	return n, nil
}
