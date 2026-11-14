// FT19 decoding adapted from Deark's fmtutil-ftcomp.c, by Dimitriy
// Ryazantcev and Jason Summers. See LICENSE.deark. Unlike the reference,
// malformed/truncated streams are errors, not silently zero-padded input.
package os2pack

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"io"
	"sync"
)

const symbols = 433

var tableOnce sync.Once
var tableError error
var descriptorWeights, digitWeights, symbolTypes [symbols]uint16
var extraSteps [129]uint16
var preset []byte

func tables() error {
	tableOnce.Do(func() {
		r, e := zlib.NewReader(bytes.NewReader(compressedTables))
		if e != nil {
			tableError = e
			return
		}
		defer r.Close()
		b, e := io.ReadAll(io.LimitReader(r, 7843))
		if e != nil || len(b) != 7842 {
			tableError = fmt.Errorf("invalid FTComp bootstrap tables")
			return
		}
		off := 0
		for _, a := range [][]uint16{descriptorWeights[:], digitWeights[:], symbolTypes[:], extraSteps[:]} {
			for i := range a {
				a[i] = binary.LittleEndian.Uint16(b[off:])
				off += 2
			}
		}
		preset = append([]byte(nil), b[off:]...)
	})
	return tableError
}

type weighted struct {
	id     int
	weight uint16
}
type huffman struct {
	children [symbols * 2][2]int
	root     int
}

// PACK2's equal-weight ordering is part of the bitstream format. Neither a
// stable generic sort nor canonical Huffman code assignment is equivalent.
func sortWeights(q []weighted, lo, hi int) {
	if lo >= hi {
		return
	}
	if hi-lo <= 16 {
		for i := lo + 1; i <= hi; i++ {
			k := q[i]
			j := lo
			for j < i && q[j].weight < k.weight {
				j++
			}
			copy(q[j+1:i+1], q[j:i])
			q[j] = k
		}
		return
	}
	pivot := q[(lo+hi)/2].weight
	l, r := lo, hi
	for l <= r {
		for q[l].weight < pivot {
			l++
		}
		for q[r].weight > pivot {
			r--
		}
		if l <= r {
			q[l], q[r] = q[r], q[l]
			l++
			r--
		}
	}
	if lo < r {
		sortWeights(q, lo, r)
	}
	if l < hi {
		sortWeights(q, l, hi)
	}
}
func buildTree(w [symbols]uint16) (*huffman, error) {
	var q [symbols + 2]weighted
	n, units, last := 0, 0, 0
	for id, weight := range w {
		carry := id
		if weight != 0 {
			if weight == 1 {
				carry = last
				q[n] = q[units]
				n++
				q[units].id = id
				units++
			} else {
				q[n].id = id
				n++
			}
		}
		last = carry
	}
	if n == 0 {
		return nil, fmt.Errorf("empty FTComp Huffman tree")
	}
	if n == 1 {
		q[1] = q[units]
		n = 2
		q[units].id = last
		units++
		w[last] = 1
	}
	for i := 0; i < n; i++ {
		q[i].weight = w[q[i].id]
	}
	sortWeights(q[:], units, n-1)
	t := new(huffman)
	next := symbols
	front := 0
	for remaining := n; remaining > 2; remaining-- {
		a, b := q[front], q[front+1]
		merged := a.weight + b.weight
		lo, hi := front+2, n
		for lo < hi {
			mid := (lo + hi) / 2
			if q[mid].weight < merged {
				lo = mid + 1
			} else {
				hi = mid
			}
		}
		front++
		copy(q[front:lo-1], q[front+1:lo])
		q[lo-1] = weighted{next, merged}
		t.children[next] = [2]int{b.id, a.id}
		next++
	}
	t.children[next] = [2]int{q[front+1].id, q[front].id}
	t.root = next
	return t, nil
}

type bitReader struct {
	data []byte
	bit  int
	err  error
}

func (b *bitReader) read(n int) int {
	if n < 0 || b.bit > len(b.data)*8-n {
		b.err = io.ErrUnexpectedEOF
		return 0
	}
	v := 0
	for i := 0; i < n; i++ {
		v = v<<1 | int((b.data[b.bit/8]>>uint(7-b.bit%8))&1)
		b.bit++
	}
	return v
}
func (b *bitReader) symbol(t *huffman) int {
	node := t.root
	for i := 0; i < symbols; i++ {
		if node < symbols {
			return node
		}
		node = t.children[node][b.read(1)]
		if b.err != nil {
			return 0
		}
	}
	b.err = fmt.Errorf("invalid FTComp Huffman path")
	return 0
}
func scaledTree(raw [symbols]uint16, m0, m1 byte) (*huffman, error) {
	var w [symbols]uint16
	var max uint16
	for i, v := range raw {
		m := m0
		if symbolTypes[i] != 0 {
			m = m1
		}
		w[i] = v * uint16(m)
		if w[i] > max {
			max = w[i]
		}
	}
	if max >= 256 {
		scale := uint32(65535 / max)
		for i, v := range w {
			n := uint32(v) * scale >> 8
			if v != 0 && n == 0 {
				n = 1
			}
			w[i] = uint16(n)
		}
	}
	return buildTree(w)
}

type recent [32]uint16

func (r *recent) push(v uint16)           { copy(r[1:], r[:31]); r[0] = v }
func (r *recent) promote(i int, v uint16) { copy(r[1:i+1], r[:i]); r[0] = v }
func appendWord(out []byte, v int) []byte { return append(out, byte(v), byte(v>>8)) }
func wordAt(out []byte, i int) (int, error) {
	if i < 0 || i+2 > len(out) {
		return 0, fmt.Errorf("invalid FTComp replay position %d/%d", i, len(out))
	}
	return int(binary.LittleEndian.Uint16(out[i:])), nil
}
func stage1(data []byte, pos int, desc, digit *huffman) ([]byte, int, error) {
	if pos < 0 || pos+4 > len(data) {
		return nil, 0, io.ErrUnexpectedEOF
	}
	length := int(binary.LittleEndian.Uint16(data[pos:]))
	pos += 2
	if length == 65535 {
		n := int(binary.LittleEndian.Uint16(data[pos:]))
		pos += 2
		if n > len(data)-pos {
			return nil, 0, io.ErrUnexpectedEOF
		}
		return data[pos : pos+n], pos + n, nil
	}
	if pos+4 > len(data) {
		return nil, 0, io.ErrUnexpectedEOF
	}
	models := data[pos : pos+4]
	pos += 4
	br := bitReader{data: data, bit: pos * 8}
	var raw [symbols]uint16
	for i := 0; i < symbols; {
		v := br.symbol(desc)
		if br.err != nil {
			return nil, 0, br.err
		}
		if v == 256 {
			i += 16
		} else {
			raw[i] = uint16(v & 255)
			i++
		}
	}
	a, e := scaledTree(raw, models[0], models[1])
	if e != nil {
		return nil, 0, e
	}
	b := a
	if (models[2] != models[1] || models[3] != models[0]) && (models[2] != 0 || models[3] != 0) {
		b, e = scaledTree(raw, models[3], models[2])
		if e != nil {
			return nil, 0, e
		}
	}
	var lengths, distances recent
	var mru [5]int // single, combine forms 0/1/2, terminal chain digit
	unrank := func(site, v int) int {
		if v == 256 {
			return mru[site]
		}
		mru[site] = v
		return v
	}
	out := make([]byte, 0, length+8)
	chain, table := 0, 0
	for len(out) < length && br.err == nil {
		if chain != 0 {
			if chain > 2 {
				v := br.symbol(digit)
				chain++
				if chain == 6 {
					v = unrank(4, v)
					chain = 0
				} else if v == 256 {
					v = 0
				} else {
					v++
				}
				out = append(out, byte(v))
			} else {
				form, imm := 0, 0
				if chain == 2 {
					if br.read(1) == 0 {
						imm = br.read(4)
					} else if br.read(1) == 0 {
						form = 1
						imm = br.read(6)
					} else {
						form = 2
						imm = br.read(7)
					}
				}
				v := br.symbol(digit)
				if chain == 1 {
					out = append(out, byte(unrank(0, v)))
				} else {
					shifts := [3]int{4, 6, 7}
					bases := [3]int{16, 68, 162}
					out = appendWord(out, ((unrank(form+1, v)+bases[form])<<shifts[form])+imm)
				}
				chain = 0
			}
			continue
		}
		tree := a
		if table != 0 {
			tree = b
		}
		sym := br.symbol(tree)
		table = int(symbolTypes[sym])
		before := len(out)
		switch {
		case sym < 256:
			out = append(out, byte(sym))
		case sym < 385:
			off := sym - 256
			out = append(out, 0x9e, byte(off))
			chain = int(extraSteps[off])
			if chain != 0 {
				lengths.push(uint16(before + 1))
			}
		case sym < 401:
			v, e := wordAt(out, before+383-sym)
			if e != nil {
				return nil, 0, e
			}
			out = appendWord(out, v)
			distances.push(uint16(v))
		case sym < 417:
			i := sym - 401
			v := distances[i]
			out = appendWord(out, int(v))
			distances.promote(i, v)
		default:
			i := sym - 417
			src := int(lengths[i])
			out = append(out, 0x9e)
			v, e := wordAt(out, src)
			if e != nil {
				return nil, 0, e
			}
			out = appendWord(out, v)
			if byte(v) == 0x80 {
				v, e = wordAt(out, src+2)
				if e != nil {
					return nil, 0, e
				}
				out = appendWord(out, v)
			} else if v&0x40 != 0 {
				if src+2 >= len(out) {
					return nil, 0, io.ErrUnexpectedEOF
				}
				out = append(out, out[src+2])
			}
			lengths.promote(i, uint16(before+1))
		}
	}
	if br.err != nil {
		return nil, 0, br.err
	}
	if len(out) != length || chain != 0 {
		return nil, 0, fmt.Errorf("FTComp stage1 length/chain mismatch: %d/%d chain %d", len(out), length, chain)
	}
	return out, (br.bit + 7) / 8, nil
}

// DecodeFT19 expands a single bounded FTComp member (including its marker).
// FT21 is deliberately rejected until its additional transform is supported.
func DecodeFT19(data []byte, size int64) ([]byte, error) {
	if size < 0 || size > 256<<20 {
		return nil, fmt.Errorf("FTComp output limit")
	}
	if len(data) < 4 {
		return nil, io.ErrUnexpectedEOF
	}
	if len(data) < 8 || string(data[4:8]) != "fT19" {
		if len(data) >= 8 && string(data[4:8]) == "fT21" {
			return nil, fmt.Errorf("FTComp fT21 unsupported")
		}
		if int64(len(data)-4) != size {
			return nil, fmt.Errorf("FTComp missing tag or stored length mismatch")
		}
		return append([]byte(nil), data[4:]...), nil
	}
	if e := tables(); e != nil {
		return nil, e
	}
	desc, e := buildTree(descriptorWeights)
	if e != nil {
		return nil, e
	}
	digit, e := buildTree(digitWeights)
	if e != nil {
		return nil, e
	}
	history := make([]byte, 65536)
	copy(history, preset)
	hp := len(preset)
	out := make([]byte, 0, int(size))
	emit := func(v byte) error {
		if int64(len(out)) >= size {
			return fmt.Errorf("FTComp output exceeds declared size")
		}
		out = append(out, v)
		history[hp&65535] = v
		hp++
		return nil
	}
	pos := 4
	for pos+4 <= len(data) && string(data[pos:pos+4]) == "fT19" {
		stream, next, e := stage1(data, pos+4, desc, digit)
		if e != nil {
			return nil, fmt.Errorf("FTComp block at %d: %w", pos, e)
		}
		pos = next
		for p := 0; p < len(stream); {
			if p+2 > len(stream) {
				return nil, io.ErrUnexpectedEOF
			}
			n := int(binary.LittleEndian.Uint16(stream[p:]))
			p += 2
			if n < 1 || n > len(stream)-p {
				return nil, fmt.Errorf("FTComp invalid chunk length %d at %d/%d", n, p, len(stream))
			}
			flag := stream[p]
			body := stream[p+1 : p+n]
			p += n
			for i := 0; i < len(body); {
				v := body[i]
				i++
				if flag == 0 || v != 0x9e {
					if e := emit(v); e != nil {
						return nil, e
					}
					continue
				}
				if i == len(body) {
					return nil, io.ErrUnexpectedEOF
				}
				f := body[i]
				i++
				if f == 0x40 {
					if e := emit(0x9e); e != nil {
						return nil, e
					}
					continue
				}
				length, dist := int(f&63)+3, 0
				if f == 0x80 {
					if i == len(body) {
						return nil, io.ErrUnexpectedEOF
					}
					length = int(body[i]) + 67
					i++
				}
				if f&0x40 == 0 && f != 0x80 {
					if i == len(body) {
						return nil, io.ErrUnexpectedEOF
					}
					dist = int(body[i])
					i++
				} else {
					if i+2 > len(body) {
						return nil, io.ErrUnexpectedEOF
					}
					dist = int(binary.LittleEndian.Uint16(body[i:]))
					i += 2
				}
				for j := 0; j < length; j++ {
					if e := emit(history[(hp-1-dist)&65535]); e != nil {
						return nil, e
					}
				}
			}
		}
	}
	if int64(len(out)) != size {
		return nil, fmt.Errorf("FTComp output size %d, want %d", len(out), size)
	}
	// PACK2 may retain a small alignment/trailer after the last block.
	return out, nil
}
