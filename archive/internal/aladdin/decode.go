// Package aladdin implements the shared Huffman/LZ mechanics recovered from
// original ADCR03 and StuffIt Installer14 loaders. No third-party decoder
// implementation is used.
package aladdin

import "fmt"

type Format int

const (
	Resource03 Format = iota
	Installer14
)

type bits struct {
	data []byte
	pos  int64
}

func (b *bits) read(n int) (uint32, error) {
	if n < 0 || n > 32 || b.pos > int64(len(b.data))*8-int64(n) {
		return 0, fmt.Errorf("aladdin: truncated bits")
	}
	var v uint32
	for i := 0; i < n; i++ {
		v |= uint32((b.data[b.pos/8]>>(b.pos%8))&1) << i
		b.pos++
	}
	return v, nil
}

type symbol struct{ length, value int }

// Equal-length ordering is part of this format: the original encoder sorts
// by length with a first-element pivot and inward scans, including swaps on
// ties. Replacing this with a stable or library sort changes the codebook.
func order(a []symbol) {
	if len(a) < 2 {
		return
	}
	l, r := 0, len(a)
	for {
		l++
		for l < len(a) && a[l].length < a[0].length {
			l++
		}
		r--
		for r > 0 && a[r].length > a[0].length {
			r--
		}
		if l >= r {
			break
		}
		a[l], a[r] = a[r], a[l]
	}
	a[0], a[r] = a[r], a[0]
	order(a[:r])
	order(a[r+1:])
}

type key struct {
	width int
	code  uint32
}
type codebook map[key]int

func makeCodes(lengths []int) (codebook, error) {
	a := make([]symbol, len(lengths))
	for i, n := range lengths {
		if n < 0 || n > 32 {
			return nil, fmt.Errorf("aladdin: invalid code length")
		}
		a[i] = symbol{n, i}
	}
	order(a)
	codes := codebook{}
	var code uint64
	previous := 0
	for _, s := range a {
		if s.length == 0 {
			continue
		}
		code <<= s.length - previous
		if code >= uint64(1)<<s.length {
			return nil, fmt.Errorf("aladdin: oversubscribed codebook")
		}
		codes[key{s.length, uint32(code)}] = s.value
		code++
		previous = s.length
	}
	return codes, nil
}
func (c codebook) read(b *bits) (int, error) {
	var code uint32
	for n := 1; n <= 32; n++ {
		v, err := b.read(1)
		if err != nil {
			return 0, err
		}
		code = code<<1 | v
		if s, ok := c[key{n, code}]; ok {
			return s, nil
		}
	}
	return 0, fmt.Errorf("aladdin: invalid Huffman symbol")
}
func lengths(b *bits, count, depth int) ([]int, error) {
	if depth > 16 {
		return nil, fmt.Errorf("aladdin: codebook nesting exceeds limit")
	}
	h, err := b.read(8)
	if err != nil {
		return nil, err
	}
	minimum := int(h>>3&7) + 1
	width := int(h>>1&3) + 2
	maximum := (1 << width) - 1
	zero := -1
	if h&1 != 0 {
		zero = maximum - 1
	}
	var codes codebook
	if h&64 != 0 {
		sub, err := lengths(b, 1<<width, depth+1)
		if err != nil {
			return nil, err
		}
		codes, err = makeCodes(sub)
		if err != nil {
			return nil, err
		}
	}
	read := func() (int, error) {
		if codes != nil {
			return codes.read(b)
		}
		v, e := b.read(width)
		return int(v), e
	}
	out := make([]int, 0, count)
	for len(out) < count {
		token, err := read()
		if err != nil {
			return nil, err
		}
		switch token {
		case zero:
			out = append(out, 0)
		case maximum:
			n, err := read()
			if err != nil {
				return nil, err
			}
			n += 3
			if len(out) == 0 || n > count-len(out) {
				return nil, fmt.Errorf("aladdin: invalid length repetition")
			}
			v := out[len(out)-1]
			for i := 0; i < n; i++ {
				out = append(out, v)
			}
		default:
			out = append(out, minimum+token)
		}
	}
	// Each serialized table ends at its next byte boundary. Unused bits are
	// not interpreted as symbols or as a new table.
	b.pos = (b.pos + 7) / 8 * 8
	return out, nil
}

// Decode expands one byte-aligned block with caller-supplied prior history.
func Decode(input, dictionary []byte, target int, format Format) ([]byte, error) {
	if target < 0 {
		return nil, fmt.Errorf("aladdin: negative target")
	}
	literalCount, distanceCount, prefix, minimumMatch := 292, 0, 1, 3
	if format == Installer14 {
		literalCount, distanceCount, prefix, minimumMatch = 308, 75, 0, 4
	} else if format != Resource03 {
		return nil, fmt.Errorf("aladdin: unknown codec")
	}
	if format == Resource03 && (len(input) == 0 || input[0] < 1 || input[0] > 16) {
		return nil, fmt.Errorf("aladdin: unsupported distance alphabet")
	}
	if format == Resource03 {
		distanceCount = int(input[0])*2 - 1
	}
	b := bits{input, int64(prefix * 8)}
	ll, err := lengths(&b, literalCount, 0)
	if err != nil {
		return nil, err
	}
	dl, err := lengths(&b, distanceCount, 0)
	if err != nil {
		return nil, err
	}
	lc, err := makeCodes(ll)
	if err != nil {
		return nil, err
	}
	dc, err := makeCodes(dl)
	if err != nil {
		return nil, err
	}
	lengthBits, lengthBase := make([]int, literalCount-256), make([]int, literalCount-256)
	distanceBits, distanceBase := make([]int, distanceCount), make([]int, distanceCount)
	base := 0
	for i := range lengthBits {
		n := 0
		if i >= 4 {
			n = (i - 4) / 4
		}
		lengthBits[i], lengthBase[i] = n, base
		base += 1 << n
	}
	base = 1
	for i := range distanceBits {
		n := 0
		if format == Installer14 {
			if i >= 3 {
				n = (i - 3) / 4
			}
		} else if i >= 1 {
			n = (i - 1) / 2
		}
		distanceBits[i], distanceBase[i] = n, base
		base += 1 << n
	}
	out := make([]byte, 0, target)
	for len(out) < target {
		s, err := lc.read(&b)
		if err != nil {
			return nil, err
		}
		if s < 256 {
			out = append(out, byte(s))
			continue
		}
		i := s - 256
		extra, err := b.read(lengthBits[i])
		if err != nil {
			return nil, err
		}
		n := lengthBase[i] + int(extra) + minimumMatch
		d, err := dc.read(&b)
		if err != nil {
			return nil, err
		}
		extra, err = b.read(distanceBits[d])
		if err != nil {
			return nil, err
		}
		distance := distanceBase[d] + int(extra)
		if n > target-len(out) {
			return nil, fmt.Errorf("aladdin: match exceeds declared output")
		}
		if distance > len(out)+len(dictionary) {
			return nil, fmt.Errorf("aladdin: match requires unavailable dictionary bytes")
		}
		for j := 0; j < n; j++ {
			p := len(out) - distance
			if p < 0 {
				out = append(out, dictionary[len(dictionary)+p])
			} else {
				out = append(out, out[p])
			}
		}
	}
	if (b.pos+7)/8 != int64(len(input)) {
		return nil, fmt.Errorf("aladdin: trailing compressed bytes")
	}
	return out, nil
}
