package bzip2

import (
	"bytes"
	std "compress/bzip2"
	"encoding/hex"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/tinyrange/trex/auto"
	starfile "github.com/tinyrange/trex/storage/star"
)

// Encoded vectors from Go's compress/bzip2 tests. Copyright The Go Authors.
// BSD license: testdata/GO-LICENSE.
const helloHex = "425a68393141592653594eece83600000251800010400006449080200031064c4101a7a9a580bb9431f8bb9229c28482776741b0"
const zerosHex = "425a683931415926535938571ce50008084000c0040008200030cc0529a60806c4201e2ee48a70a12070ae39ca"

func vector(t *testing.T, s string) []byte {
	t.Helper()
	b, e := hex.DecodeString(s)
	if e != nil {
		t.Fatal(e)
	}
	return b
}

// Join independent fixture blocks into one stream, with a combined CRC and
// without padding between blocks, exercising non-byte-aligned boundaries.
func multi(t *testing.T, count int) []byte {
	t.Helper()
	out := []byte("BZh9")
	bit := 32
	put := func(v uint64, n int) {
		for j := n - 1; j >= 0; j-- {
			if bit/8 == len(out) {
				out = append(out, 0)
			}
			out[bit/8] |= byte((v>>j)&1) << uint(7-bit%8)
			bit++
		}
	}
	var crc uint32
	for i := 0; i < count; i++ {
		s := zerosHex
		if i%2 != 0 {
			s = helloHex
		}
		b := vector(t, s)
		end := -1
		for j := 32; j+80 <= len(b)*8; j++ {
			var v uint64
			for k := 0; k < 48; k++ {
				v = v<<1 | uint64(b[(j+k)/8]>>uint(7-(j+k)%8)&1)
			}
			if v == endMagic {
				end = j
				break
			}
		}
		if end < 0 {
			t.Fatal("fixture trailer")
		}
		for j := 32; j < end; j++ {
			put(uint64(b[j/8]>>uint(7-j%8)&1), 1)
		}
		c := uint32(b[10])<<24 | uint32(b[11])<<16 | uint32(b[12])<<8 | uint32(b[13])
		crc = (crc<<1 | crc>>31) ^ c
	}
	put(endMagic, 48)
	put(uint64(crc), 32)
	return out
}

type counted struct {
	*starfile.Bytes
	readBytes atomic.Int64
}

func (c *counted) ReadAt(p []byte, o int64) (int, error) {
	n, e := c.Bytes.ReadAt(p, o)
	c.readBytes.Add(int64(n))
	return n, e
}
func TestIndexedReadsAndBoundedCache(t *testing.T) {
	encoded := multi(t, 10)
	want, e := io.ReadAll(std.NewReader(bytes.NewReader(encoded)))
	if e != nil {
		t.Fatal(e)
	}
	source := &counted{Bytes: &starfile.Bytes{Data: encoded}}
	r := NewReader(source, 16<<20)
	if n := r.Size(); n != int64(len(want)) {
		t.Fatalf("size=%d error=%v", n, r.err)
	}
	if r.cached > cacheBytes {
		t.Fatalf("cache=%d", r.cached)
	}
	// The first block was evicted; returning to it reads only that compressed
	// block, without rescanning or decoding the preceding stream.
	before := source.readBytes.Load()
	got := make([]byte, 128)
	if _, e := r.ReadAt(got, 123); e != nil || !bytes.Equal(got, want[123:251]) {
		t.Fatal("backward read", e)
	}
	max := (r.blocks[0].end - r.blocks[0].start + r.blocks[0].start%8 + 7) / 8
	if int64(source.readBytes.Load()-before) > max {
		t.Fatalf("reread %d bytes, block has %d", source.readBytes.Load()-before, max)
	}
	var wg sync.WaitGroup
	for _, off := range []int64{0, (1 << 20) - 10, (2 << 20) + 10, int64(len(want)) - 30} {
		wg.Add(1)
		go func(off int64) {
			defer wg.Done()
			b := make([]byte, 20)
			_, e := r.ReadAt(b, off)
			if e != nil || !bytes.Equal(b, want[off:off+20]) {
				t.Errorf("offset %d: %v", off, e)
			}
		}(off)
	}
	wg.Wait()
}
func TestConcatenatedEmptyCorruptAndLimit(t *testing.T) {
	hello := vector(t, helloHex)
	for _, b := range [][]byte{hello, append(append([]byte{}, hello...), hello...), {'B', 'Z', 'h', '9', 0x17, 0x72, 0x45, 0x38, 0x50, 0x90, 0, 0, 0, 0}} {
		want, e := io.ReadAll(std.NewReader(bytes.NewReader(b)))
		if e != nil {
			t.Fatal(e)
		}
		r := NewReader(&starfile.Bytes{Data: b}, 1<<20)
		if r.Size() != int64(len(want)) {
			t.Fatal("size", r.err)
		}
		got := make([]byte, len(want))
		if _, e := r.ReadAt(got, 0); e != nil || !bytes.Equal(got, want) {
			t.Fatal(e)
		}
	}
	r := NewReader(&starfile.Bytes{Data: vector(t, zerosHex)}, 100)
	if _, e := r.ReadAt(make([]byte, 1), 0); !errors.Is(e, auto.ErrLimit) {
		t.Fatalf("limit %v", e)
	}
	bad := append([]byte{}, hello...)
	bad[10] ^= 1
	r = NewReader(&starfile.Bytes{Data: bad}, 1<<20)
	if _, e := r.ReadAt(make([]byte, 1), 0); e == nil {
		t.Fatal("bad CRC accepted")
	}
}
func TestAutoBzip2NestedContainer(t *testing.T) {
	// The raw bytes stay available even after opening the decoded view.
	b := multi(t, 2)
	node := auto.Open(&starfile.Bytes{Data: b}, "data.bz2", auto.Options{MaxExpandedBytes: 2 << 20})
	m, e := node.Metadata()
	if e != nil || m.Format != "bzip2" {
		t.Fatal(m, e)
	}
	raw, e := starfile.ReadAll(node.Reader())
	if e != nil || !bytes.Equal(raw, b) {
		t.Fatal("raw bytes", e)
	}
}
