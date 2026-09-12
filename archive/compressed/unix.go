package compressed

import (
	"fmt"
	"github.com/tinyrange/trex/storage"
	"io"
)

// unixReader implements the UNIX compress .Z variant of LZW. Unlike GIF/PDF
// LZW, widths change at dictionary boundaries and packing is aligned to groups
// of eight codes at width changes and CLEAR. There is no end code or checksum.
type unixReader struct {
	source                    io.Reader
	maximum, width, next, old int
	block                     bool
	group                     [16]byte
	available, bit            int
	prefix                    []uint16
	suffix                    []byte
	stack                     []byte
	pending                   []byte
	finished                  bool
	zeroPadding               bool
}

func newUnixReader(source storage.Reader) (io.Reader, error) {
	var h [3]byte
	if _, err := source.ReadAt(h[:], 0); err != nil {
		return nil, err
	}
	bits := int(h[2] & 31)
	if h[0] != 0x1f || h[1] != 0x9d || h[2]&0x60 != 0 || bits < 9 || bits > 16 {
		return nil, fmt.Errorf("compress: invalid header")
	}
	r := &unixReader{source: io.NewSectionReader(source, 3, source.Size()-3), maximum: bits, width: 9, old: -1, block: h[2]&0x80 != 0, prefix: make([]uint16, 1<<bits), suffix: make([]byte, 1<<bits), stack: make([]byte, 1<<bits)}
	r.next = 256
	if r.block {
		r.next = 257
	}
	return r, nil
}

func (r *unixReader) code() (int, error) {
	if r.next > (1<<r.width)-1 && r.width < r.maximum {
		r.width++
		r.available = 0
		r.bit = 0
	}
	if r.bit+r.width > r.available {
		if r.finished {
			return 0, io.EOF
		}
		n, err := io.ReadFull(r.source, r.group[:r.width])
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return 0, err
		}
		r.available = n * 8
		r.bit = 0
		r.finished = err != nil
		if r.available < r.width {
			if r.available != 0 {
				// Some fixed-block media packages pad the entire .Z stream
				// with zero bytes. Complete zero codes are decoded normally;
				// only a final incomplete all-zero code is padding. Callers
				// must validate the enclosing package inventory separately.
				if r.zeroPadding && r.old >= 0 {
					zero := true
					for _, b := range r.group[:n] {
						zero = zero && b == 0
					}
					if zero {
						return 0, io.EOF
					}
				}
				return 0, fmt.Errorf("compress: truncated code")
			}
			return 0, io.EOF
		}
	}
	c := 0
	for bit := 0; bit < r.width; bit++ {
		pos := r.bit + bit
		c |= int((r.group[pos/8]>>uint(pos%8))&1) << uint(bit)
	}
	r.bit += r.width
	return c, nil
}

func (r *unixReader) Read(p []byte) (int, error) {
	n := 0
	for len(p) > 0 {
		if len(r.pending) > 0 {
			count := copy(p, r.pending)
			p = p[count:]
			r.pending = r.pending[count:]
			n += count
			continue
		}
		c, err := r.code()
		if err != nil {
			return n, err
		}
		if r.block && c == 256 {
			r.width = 9
			r.next = 257
			r.old = -1
			r.available = 0
			r.bit = 0
			continue
		}
		if r.old < 0 {
			if c >= 256 {
				return n, fmt.Errorf("compress: first code is not literal")
			}
			r.stack[len(r.stack)-1] = byte(c)
			r.pending = r.stack[len(r.stack)-1:]
			r.old = c
			continue
		}
		original := c
		pos := len(r.stack)
		if c > r.next || c >= len(r.prefix) {
			return n, fmt.Errorf("compress: invalid dictionary code %d", c)
		}
		special := c == r.next
		if special {
			c = r.old
			pos--
		}
		for c >= 256 {
			if c >= r.next || pos <= 0 {
				return n, fmt.Errorf("compress: invalid dictionary chain")
			}
			pos--
			r.stack[pos] = r.suffix[c]
			parent := int(r.prefix[c])
			if parent >= c {
				return n, fmt.Errorf("compress: cyclic dictionary")
			}
			c = parent
		}
		if pos <= 0 {
			return n, fmt.Errorf("compress: string too long")
		}
		pos--
		r.stack[pos] = byte(c)
		if special {
			r.stack[len(r.stack)-1] = byte(c)
		}
		if r.next < len(r.prefix) {
			r.prefix[r.next] = uint16(r.old)
			r.suffix[r.next] = byte(c)
			r.next++
		}
		r.old = original
		r.pending = r.stack[pos:]
	}
	return n, nil
}
