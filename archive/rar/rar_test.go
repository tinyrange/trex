package rar

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"io"
	"testing"
)

type memory struct{ *bytes.Reader }

type countedMemory struct {
	memory
	read int
}

func (m *countedMemory) ReadAt(p []byte, off int64) (int, error) {
	n, err := m.memory.ReadAt(p, off)
	m.read += n
	return n, err
}

func TestStoredRangeDoesNotReplayPrefix(t *testing.T) {
	data := bytes.Repeat([]byte("archive-range"), 300000)
	source := &countedMemory{memory: memory{bytes.NewReader(append([]byte("Rar!\x1a\x07\x00"), stored4("large", data)...))}}
	a, err := Open(source, 10)
	if err != nil {
		t.Fatal(err)
	}
	source.read = 0
	got := make([]byte, 17)
	offset := int64(len(data) - len(got))
	if _, err := a.Files[0].ReadAt(got, offset); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data[offset:]) || source.read != len(got) {
		t.Fatalf("range read fetched %d source bytes, want %d", source.read, len(got))
	}
	corrupt := append([]byte(nil), data...)
	corrupt[len(corrupt)-1] ^= 1
	bad := append([]byte("Rar!\x1a\x07\x00"), stored4("bad", data)...)
	copy(bad[len(bad)-len(data):], corrupt)
	b, err := Open(memory{bytes.NewReader(bad)}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Files[0].ReadAt(make([]byte, len(data)), 0); err == nil {
		t.Fatal("full stored range did not check CRC")
	}
}

func (m memory) Size() int64 { return m.Reader.Size() }
func block4(kind byte, flags uint16, body []byte) []byte {
	b := make([]byte, 7)
	b[2] = kind
	binary.LittleEndian.PutUint16(b[3:], flags)
	binary.LittleEndian.PutUint16(b[5:], uint16(7+len(body)))
	b = append(b, body...)
	binary.LittleEndian.PutUint16(b, uint16(crc32.ChecksumIEEE(b[2:])))
	return b
}
func stored4(name string, data []byte) []byte {
	b := make([]byte, 25)
	binary.LittleEndian.PutUint32(b, uint32(len(data)))
	binary.LittleEndian.PutUint32(b[4:], uint32(len(data)))
	b[8] = 2
	binary.LittleEndian.PutUint32(b[9:], crc32.ChecksumIEEE(data))
	b[17] = 20
	b[18] = 0x30
	binary.LittleEndian.PutUint16(b[19:], uint16(len(name)))
	b = append(b, name...)
	return append(block4(0x74, 0x8000, b), data...)
}
func vint(v uint64) []byte {
	var b [10]byte
	n := binary.PutUvarint(b[:], v)
	return append([]byte{}, b[:n]...)
}
func block5(body []byte) []byte {
	h := append(vint(uint64(len(body))), body...)
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, crc32.ChecksumIEEE(h))
	return append(b, h...)
}
func stored5(name string, data []byte) []byte {
	b := []byte{2, 2}
	b = append(b, vint(uint64(len(data)))...)
	b = append(b, 4)
	b = append(b, vint(uint64(len(data)))...)
	b = append(b, 0)
	var crc [4]byte
	binary.LittleEndian.PutUint32(crc[:], crc32.ChecksumIEEE(data))
	b = append(b, crc[:]...)
	b = append(b, 0, 0)
	b = append(b, vint(uint64(len(name)))...)
	b = append(b, name...)
	return append(block5(b), data...)
}
func TestStoredChecksumsAndBoundedRandomAccess(t *testing.T) {
	data := make([]byte, 3<<20)
	for i := range data {
		data[i] = byte(i*37 + i/257)
	}
	for _, version := range []int{4, 5} {
		var b []byte
		if version == 4 {
			b = []byte("Rar!\x1a\x07\x00")
			b = append(b, block4(0x73, 0, make([]byte, 6))...)
			b = append(b, stored4("dir/data.bin", data)...)
			b = append(b, stored4("empty", nil)...)
			b = append(b, block4(0x7b, 0, nil)...)
		} else {
			b = []byte("Rar!\x1a\x07\x01\x00")
			b = append(b, block5([]byte{1, 0, 0})...)
			b = append(b, stored5("dir/data.bin", data)...)
			b = append(b, stored5("empty", nil)...)
			b = append(b, block5([]byte{5, 0, 0})...)
		}
		a, e := Open(memory{bytes.NewReader(b)}, 10)
		if e != nil {
			t.Fatal(version, e)
		}
		if len(a.Files) != 2 {
			t.Fatal(len(a.Files))
		}
		f := a.Files[0]
		for _, off := range []int64{0, pageSize - 3, int64(len(data)) - 7, 0, pageSize + 3} {
			p := make([]byte, 37)
			n, e := f.ReadAt(p, off)
			want := min(len(p), len(data)-int(off))
			if n != want || !bytes.Equal(p[:n], data[off:off+int64(n)]) {
				t.Fatal(version, off, n, e)
			}
			if n < len(p) && e != io.EOF {
				t.Fatal(e)
			}
		}
		if e = f.Verify(); e != nil {
			t.Fatal(e)
		}
		if e = a.Files[1].Verify(); e != nil {
			t.Fatal(e)
		}
		for off := int64(0); off < f.Size(); off += pageSize {
			p := make([]byte, 1)
			if _, e = f.ReadAt(p, off); e != nil {
				t.Fatal(e)
			}
		}
		if s := a.cache.Stats(); s.Bytes > 2<<20 {
			t.Fatal(s)
		}
		if _, e = Open(memory{bytes.NewReader(b)}, 1); e == nil {
			t.Fatal("entry limit ignored")
		}
		bad := append([]byte{}, b...)
		bad[f.Offset+int64(len(data))-1] ^= 1
		corrupt, e := Open(memory{bytes.NewReader(bad)}, 10)
		if e != nil {
			t.Fatal(e)
		}
		if e = corrupt.Files[0].Verify(); e == nil {
			t.Fatal("data CRC not checked")
		}
		bad = append([]byte{}, b...)
		bad[f.Offset-1] ^= 1
		if _, e = Open(memory{bytes.NewReader(bad)}, 10); e == nil {
			t.Fatal("header CRC not checked")
		}
		for _, n := range []int{0, 6, 10, int(f.Offset) - 1, int(f.Offset) + 5} {
			if _, e = Open(memory{bytes.NewReader(b[:n])}, 10); e == nil {
				t.Fatalf("v%d truncation %d accepted", version, n)
			}
		}
	}
}
func TestUnicodeName(t *testing.T) {
	// High-byte mode encodes U+0410 and literal mode supplies ASCII A.
	name, e := unicodeName([]byte{'?', 'A', 0, 4, 0x40, 0x10, 'A'})
	if e != nil || name != "АA" {
		t.Fatalf("%q %v", name, e)
	}
	if _, e = unicodeName([]byte{'a', 0, 0, 0xc0, 127}); e == nil {
		t.Fatal("invalid run accepted")
	}
}
func FuzzHeaders(f *testing.F) {
	f.Add(append([]byte("Rar!\x1a\x07\x00"), stored4("a", []byte("abc"))...))
	f.Add(append([]byte("Rar!\x1a\x07\x01\x00"), stored5("a", []byte("abc"))...))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			return
		}
		Headers(memory{bytes.NewReader(b)}, 100)
	})
}

// Encode a literal-only RAR3 LZ block directly from the wire grammar. This
// fixture is independent of the adapted decoder and needs no external encoder.
func literalBlock(plain []byte) []byte {
	var out []byte
	used := 0
	put := func(v, n int) {
		for bit := n - 1; bit >= 0; bit-- {
			if used%8 == 0 {
				out = append(out, 0)
			}
			out[len(out)-1] |= byte((v>>bit)&1) << uint(7-used%8)
			used++
		}
	}
	put(0, 2) // LZ mode, replace previous table.
	for i := 0; i < 20; i++ {
		if i < 16 {
			put(4, 4)
		} else {
			put(0, 4)
		}
	}
	for i := 0; i < 404; i++ {
		if i < 299 {
			put(9, 4)
		} else {
			put(0, 4)
		}
	}
	for _, b := range plain {
		put(int(b), 9)
	}
	put(256, 9)
	put(1, 2) // End of file and table.
	return out
}
func TestCompressedCRCAndTruncation(t *testing.T) {
	plain := bytes.Repeat([]byte("native RAR literal test"), 10000)
	packed := literalBlock(plain)
	makeArchive := func(payload []byte) []byte {
		b := stored4("literal.txt", plain)
		headerSize := int(binary.LittleEndian.Uint16(b[5:]))
		b = b[:headerSize]
		binary.LittleEndian.PutUint32(b[7:], uint32(len(payload)))
		b[24] = 29
		b[25] = 0x33
		binary.LittleEndian.PutUint16(b, uint16(crc32.ChecksumIEEE(b[2:])))
		b = append(b, payload...)
		return append([]byte("Rar!\x1a\x07\x00"), b...)
	}
	a, e := Open(memory{bytes.NewReader(makeArchive(packed))}, 10)
	if e != nil {
		t.Fatal(e)
	}
	if e = a.Files[0].Verify(); e != nil {
		t.Fatal(e)
	}
	for _, off := range []int64{pageSize - 3, 1, 2 * pageSize, 0} {
		p := make([]byte, 11)
		if _, e = a.Files[0].ReadAt(p, off); e != nil || !bytes.Equal(p, plain[off:off+11]) {
			t.Fatal(off, e)
		}
	}
	a, e = Open(memory{bytes.NewReader(makeArchive(packed[:len(packed)-3]))}, 10)
	if e != nil {
		t.Fatal(e)
	}
	if e = a.Files[0].Verify(); e == nil {
		t.Fatal("compressed truncation accepted")
	}
}
