package ziparchive

import (
	"archive/zip"
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"math/bits"
	"testing"

	"github.com/tinyrange/trex/auto"
)

type testBits struct {
	data []byte
	bits uint64
	n    uint
}

func (w *testBits) put(v uint64, n uint) {
	w.bits |= v << w.n
	w.n += n
	for w.n >= 8 {
		w.data = append(w.data, byte(w.bits))
		w.bits >>= 8
		w.n -= 8
	}
}
func (w *testBits) finish() []byte {
	if w.n > 0 {
		w.data = append(w.data, byte(w.bits))
		w.bits = 0
		w.n = 0
	}
	return w.data
}
func shrinkCodes(codes ...int) []byte {
	w := new(testBits)
	width := uint(9)
	control := false
	for _, c := range codes {
		w.put(uint64(c), width)
		if control {
			if c == 1 {
				width++
			}
			control = false
		} else if c == 256 {
			control = true
		}
	}
	return w.finish()
}
func legacyFixture(t *testing.T, raw, want []byte, method, flags uint16) ([]byte, *Entry) {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	h := &zip.FileHeader{Name: "payload.bin", Method: method, Flags: flags, CRC32: crc32.ChecksumIEEE(want), CompressedSize64: uint64(len(raw)), UncompressedSize64: uint64(len(want))}
	f, err := w.CreateRaw(h)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	data := buf.Bytes()
	z, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	return data, NewEntry(z.File[0])
}
func checkLegacy(t *testing.T, raw, want []byte, method, flags uint16) {
	t.Helper()
	data, f := legacyFixture(t, raw, want, method, flags)
	// Probe random slices before exact/full reads and Verify.
	for _, off := range []int{len(want) / 2, 0, max(0, len(want)-2), 1, 0} {
		if off >= len(want) {
			continue
		}
		buf := make([]byte, min(17, len(want)-off))
		n, err := f.ReadAt(buf, int64(off))
		if err != nil || n != len(buf) || !bytes.Equal(buf, want[off:off+n]) {
			t.Fatalf("slice %d: %x, %v", off, buf, err)
		}
	}
	if err := f.Verify(); err != nil || !f.verified {
		t.Fatalf("verify: %v", err)
	}
	got := make([]byte, len(want))
	if n, err := f.ReadAt(got, 0); err != nil || n != len(got) || !bytes.Equal(got, want) {
		t.Fatalf("exact read: %d %v", n, err)
	}
	// All auto and Starlark users share NewEntry's decoder, not just archive.zip.
	detected, err := auto.Identify(bytes.NewReader(data), auto.Options{})
	if err != nil || detected.Format != "zip" {
		t.Fatalf("auto: %v %v", detected, err)
	}
	children, err := auto.Open(bytes.NewReader(data), "test.zip", auto.Options{}).Children()
	if err != nil || len(children) != 1 {
		t.Fatalf("auto children: %v", err)
	}
	member := children[0].Reader()
	got = make([]byte, member.Size())
	if n, e := member.ReadAt(got, 0); e != nil || n != len(got) || !bytes.Equal(got, want) {
		t.Fatalf("auto payload: %d %v", n, e)
	}
}
func TestShrinkCodes(t *testing.T) {
	cases := []struct {
		name  string
		codes []int
		want  string
	}{
		{"literals", []int{65, 66, 67}, "ABC"},
		{"KwKwK", []int{65, 257, 258}, "AAAAAA"},
		{"width", []int{65, 256, 1, 66, 257}, "ABAB"},
		{"clear and reuse", []int{65, 66, 257, 65, 256, 2, 66, 258}, "ABABABAB"},
		{"all widths", []int{65, 256, 1, 256, 1, 256, 1, 256, 1, 66, 257}, "ABAB"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) { checkLegacy(t, shrinkCodes(tt.codes...), []byte(tt.want), 1, 0) })
	}
	checkLegacy(t, nil, nil, 1, 0)
}

// Fixed, balanced trees encode symbol s as the bit-reversal of its complement.
// These synthetic vectors exercise all four flag combinations, overlapping
// matches, extended lengths, zero prehistory and dictionary wraparound.
func implodeVector(flags uint16) ([]byte, []byte) {
	var raw []byte
	coded := flags&4 != 0
	if coded {
		raw = append(raw, 15)
		raw = append(raw, bytes.Repeat([]byte{0xf7}, 16)...)
	}
	for i := 0; i < 2; i++ {
		raw = append(raw, 3, 0xf5, 0xf5, 0xf5, 0xf5)
	}
	w := new(testBits)
	symbol := func(v int, n uint) { w.put(uint64(bits.Reverse16(uint16(v^((1<<n)-1)))>>(16-n)), n) }
	low := uint(6)
	if flags&2 != 0 {
		low = 7
	}
	minimum := 2
	if coded {
		minimum = 3
	}
	match := func(distance, length int) {
		w.put(0, 1)
		w.put(uint64((distance-1)&((1<<low)-1)), low)
		symbol((distance-1)>>low, 6)
		l := length - minimum
		symbol(min(l, 63), 6)
		if l >= 63 {
			w.put(uint64(l-63), 8)
		}
	}
	var want []byte
	match(1, minimum)
	want = append(want, make([]byte, minimum)...)
	for i := 0; i < 9000; i++ {
		v := i % 251
		w.put(1, 1)
		if coded {
			symbol(v, 8)
		} else {
			w.put(uint64(v), 8)
		}
		want = append(want, byte(v))
	}
	match(1, minimum+63+255)
	want = append(want, bytes.Repeat(want[len(want)-1:], minimum+63+255)...)
	distance := 1 << (low + 6)
	match(distance, minimum)
	for i := 0; i < minimum; i++ {
		want = append(want, want[len(want)-distance])
	}
	raw = append(raw, w.finish()...)
	return raw, want
}
func TestImplodeFlagsAndWindow(t *testing.T) {
	for _, flags := range []uint16{0, 2, 4, 6} {
		raw, want := implodeVector(flags)
		checkLegacy(t, raw, want, 6, flags)
	}
}
func TestLegacyMalformedAndChecksum(t *testing.T) {
	impl, want := implodeVector(0)
	for _, tt := range []struct {
		raw, want []byte
		method    uint16
	}{
		{shrinkCodes(65, 257), []byte("AAA"), 1}, {impl, want, 6},
	} {
		for _, mutate := range []func(*Entry){
			func(f *Entry) { f.entry.CRC32 ^= 1 },
			func(f *Entry) { f.entry.UncompressedSize64++ },
			func(f *Entry) { f.entry.UncompressedSize64-- },
			func(f *Entry) { f.entry.Flags |= 1 },
		} {
			_, f := legacyFixture(t, tt.raw, tt.want, tt.method, 0)
			mutate(f)
			if err := f.Verify(); err == nil {
				t.Fatal("accepted invalid metadata or CRC")
			}
			if _, err := f.ReadAt(make([]byte, 1), 0); err == nil {
				t.Fatal("served bytes after failure")
			}
		}
		for _, raw := range [][]byte{tt.raw[:len(tt.raw)-1], append(bytes.Clone(tt.raw), 0)} {
			_, f := legacyFixture(t, raw, tt.want, tt.method, 0)
			if err := f.Verify(); err == nil {
				t.Fatal("accepted truncated/trailing payload")
			}
		}
	}
	for _, raw := range [][]byte{shrinkCodes(257), shrinkCodes(65, 299), shrinkCodes(65, 256, 3), shrinkCodes(65, 256, 1, 256, 1, 256, 1, 256, 1, 256, 1)} {
		_, f := legacyFixture(t, raw, make([]byte, 32), 1, 0)
		if err := f.Verify(); err == nil {
			t.Fatal("accepted invalid shrink codes")
		}
	}
	for _, raw := range [][]byte{{0}, {0, 0x05}, {3, 0xf0, 0xf0, 0xf0, 0xf0}, {3, 0xff, 0xff, 0xff, 0xff}, {4, 0xf5, 0xf5, 0xf5, 0xf5, 0xf5}} {
		_, f := legacyFixture(t, raw, []byte("x"), 6, 0)
		if err := f.Verify(); err == nil {
			t.Fatal("accepted invalid implode tree")
		}
	}
	// Verify must check CRC even for empty streams.
	_, empty := legacyFixture(t, nil, nil, 1, 0)
	empty.entry.CRC32 = 1
	if err := empty.Verify(); !errors.Is(err, zip.ErrChecksum) {
		t.Fatalf("empty CRC: %v", err)
	}
}
func TestImplodeNonuniformTree(t *testing.T) {
	// 16 length-6, 16 length-7, 16 length-5, then 16 length-7 codes: a complete,
	// nonuniform tree. The canonical ordering is intentionally not symbol order.
	raw := []byte{3, 0xf5, 0xf6, 0xf4, 0xf6}
	b := &zipBits{r: bufio.NewReader(bytes.NewReader(raw))}
	var tree implodeTree
	if err := tree.load(b, 64); err != nil {
		t.Fatal(err)
	}
	w := new(testBits)
	// Symbol 32 has canonical 00000, symbol 0 has canonical 100000.
	w.put(31, 5)
	w.put(62, 6)
	b = &zipBits{r: bufio.NewReader(bytes.NewReader(w.finish()))}
	for _, want := range []int{32, 0} {
		got, err := tree.read(b)
		if err != nil || got != want {
			t.Fatalf("got %d %v, want %d", got, err, want)
		}
	}
}
func FuzzLegacyZIP(f *testing.F) {
	f.Add(uint8(1), uint8(0), uint16(6), shrinkCodes(65, 257, 258))
	raw, want := implodeVector(0)
	f.Add(uint8(6), uint8(0), uint16(len(want)), raw)
	f.Fuzz(func(t *testing.T, method, flags uint8, size uint16, raw []byte) {
		if method != 1 && method != 6 {
			return
		}
		_, entry := legacyFixture(t, raw, make([]byte, int(size)), uint16(method), uint16(flags&6))
		// The declared output bound is small irrespective of compressed input.
		entry.Verify()
		if len(entry.data) > decodedWindow {
			t.Fatal("unbounded cache")
		}
	})
}

// Keep binary/descriptor corruption coverage independent of the writer's CRC.
func TestLegacyCentralChecksum(t *testing.T) {
	data, _ := legacyFixture(t, shrinkCodes(65), []byte("A"), 1, 0)
	central := bytes.Index(data, []byte("PK\x01\x02"))
	binary.LittleEndian.PutUint32(data[central+16:], 0)
	z, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewEntry(z.File[0]).open()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err = io.ReadAll(r); !errors.Is(err, zip.ErrChecksum) {
		t.Fatalf("CRC: %v", err)
	}
}
