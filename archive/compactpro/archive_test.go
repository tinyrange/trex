package compactpro

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
)

type testBits struct {
	data []byte
	bit  int
}

func (w *testBits) put(v, n int) {
	for i := n - 1; i >= 0; i-- {
		if w.bit%8 == 0 {
			w.data = append(w.data, 0)
		}
		w.data[w.bit/8] |= byte(v>>uint(i)&1) << uint(7-w.bit%8)
		w.bit++
	}
}
func (w *testBits) header() int {
	for _, v := range []struct{ n, length int }{{128, 8}, {32, 6}, {64, 7}} {
		w.put(v.n, 8)
		for i := 0; i < v.n; i++ {
			w.put(v.length<<4|v.length, 8)
		}
	}
	return w.bit / 8
}
func (w *testBits) literal(v byte) { w.put(1, 1); w.put(int(v), 8) }
func (w *testBits) match(n, distance int) {
	w.put(0, 1)
	w.put(n, 6)
	w.put(distance>>6, 7)
	w.put(distance&63, 6)
}
func (w *testBits) padding(start int) {
	end := int(paddedEnd(int64(w.bit), int64(start)))
	for len(w.data) < end {
		w.data = append(w.data, 0)
	}
	w.bit = end * 8
}

func TestLZHAndRLE(t *testing.T) {
	w := testBits{}
	start := w.header()
	w.literal('A')
	w.match(5, 1)
	w.literal(0x81)
	w.literal(0x82)
	w.literal(4)
	w.padding(start)
	got, err := decode(w.data, 9, true)
	if err != nil || string(got) != "AAAAAAAAA" {
		t.Fatalf("%q %v", got, err)
	}
	for _, bad := range [][]byte{w.data[:len(w.data)-1], append(append([]byte{}, w.data...), 0), {129}} {
		if _, err := decode(bad, 9, true); err == nil {
			t.Fatalf("accepted malformed input %x", bad)
		}
	}
	bad := testBits{}
	start = bad.header()
	bad.match(0, 1)
	bad.padding(start)
	if _, err := decode(bad.data, 3, true); err == nil {
		t.Fatal("accepted invalid history")
	}
}

func TestInitialZeroWindow(t *testing.T) {
	w := testBits{}
	start := w.header()
	w.match(3, 34)
	w.padding(start)
	got, err := decode(w.data, 3, true)
	if err != nil || !bytes.Equal(got, []byte{0, 0, 0}) {
		t.Fatalf("%x %v", got, err)
	}
}

func TestZeroOffsetRingSlot(t *testing.T) {
	w := testBits{}
	start := w.header()
	w.literal('A')
	for i := 0; i < 8191; i++ {
		w.literal(0)
	}
	w.match(3, 0)
	w.padding(start)
	got, err := decode(w.data, 8195, true)
	if err != nil || !bytes.Equal(got[8192:], []byte{'A', 0, 0}) {
		t.Fatalf("size%d %v", len(got), err)
	}
}
func TestBlockTransition(t *testing.T) {
	w := testBits{}
	start := w.header()
	for i := 0; i < 65528; i++ {
		w.literal('A')
	}
	w.padding(start)
	start = w.header()
	w.match(4, 1)
	w.padding(start)
	got, err := decode(w.data, 65532, true)
	if err != nil || !bytes.Equal(got, bytes.Repeat([]byte{'A'}, 65532)) {
		t.Fatalf("size%d: %v", len(got), err)
	}
}
func TestRLE(t *testing.T) {
	for _, tc := range []struct{ input, want []byte }{
		{[]byte{'A', 0x81, 0x82, 4}, []byte("AAAA")},
		{[]byte{0x81, 0x82, 0, 0x81, 0x82, 3}, []byte{0x81, 0x82, 0x82, 0x82}},
		{[]byte{0x81, 0x81, 0x82, 3}, []byte{0x81, 0x81, 0x81}},
		{[]byte{0x81, 'A', 0x81}, []byte{0x81, 'A', 0x81}},
	} {
		got, err := decode(tc.input, len(tc.want), false)
		if err != nil || !bytes.Equal(got, tc.want) {
			t.Fatalf("%x: %x %v", tc.input, got, err)
		}
	}
	for _, b := range [][]byte{{0x81, 0x82}, {0x81, 0x82, 2}, {'A', 0x81, 0x82, 255}} {
		if _, err := decode(b, 4, false); err == nil {
			t.Fatalf("accepted %x", b)
		}
	}
	w := testBits{}
	start := w.header()
	w.literal(0x81)
	w.padding(start)
	got, err := decode(w.data, 1, true)
	if err != nil || !bytes.Equal(got, []byte{0x81}) {
		t.Fatalf("terminal escape: %x %v", got, err)
	}
}
func archiveSample() []byte {
	be := binary.BigEndian
	// Directory D contains F; resource fork 'rr', data fork 'ddd'.
	data := []byte{'r', 'r', 'd', 0x81, 0x82, 3}
	b := make([]byte, 8)
	b[0], b[1] = 1, 1
	be.PutUint32(b[4:], uint32(8+len(data)))
	b = append(b, data...)
	c := make([]byte, 7)
	be.PutUint16(c[4:], 2)
	c = append(c, 0x81, 'D', 0, 1, 1, 'F')
	v := make([]byte, 45)
	v[0] = 1
	be.PutUint32(v[1:], 8)
	copy(v[5:], "TEXTttxt")
	be.PutUint32(v[13:], 100)
	be.PutUint32(v[17:], 200)
	be.PutUint32(v[23:], ^crc32.ChecksumIEEE([]byte("rrddd")))
	be.PutUint32(v[29:], 2)
	be.PutUint32(v[33:], 3)
	be.PutUint32(v[37:], 2)
	be.PutUint32(v[41:], 4)
	c = append(c, v...)
	be.PutUint32(c, ^crc32.ChecksumIEEE(c[4:]))
	return append(b, c...)
}
func TestArchive(t *testing.T) {
	a, err := Open(&starfile.Bytes{Data: archiveSample()}, 2, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Entries) != 2 || a.Entries[1].Path != "/D/F" {
		t.Fatalf("%+v", a)
	}
	e := a.Entries[1]
	r, _ := starfile.ReadAll(e.Resource)
	d, _ := starfile.ReadAll(e.Data)
	if string(r) != "rr" || string(d) != "ddd" || e.Created != 100 || e.Modified != 200 || string(e.Type[:]) != "TEXT" {
		t.Fatalf("%+v %q %q", e, r, d)
	}
	if _, err := Open(&starfile.Bytes{Data: archiveSample()}, 1, 1000); err == nil {
		t.Fatal("entry limit ignored")
	}
	if _, err := Open(&starfile.Bytes{Data: archiveSample()}, 2, 4); err == nil {
		t.Fatal("size limit ignored")
	}
	if component([]byte("a/%\xff")) != "a%2F%25%FF" || component([]byte("..")) != "%2E%2E" {
		t.Fatal("name escaping")
	}
}
func TestMalformedArchive(t *testing.T) {
	be := binary.BigEndian
	for name, mutate := range map[string]func([]byte){
		"signature": func(b []byte) { b[0] = 0 }, "volume": func(b []byte) { b[1] = 2 },
		"catalog CRC": func(b []byte) { b[14] ^= 1 }, "payload CRC": func(b []byte) { b[8] ^= 1 },
		"directory": func(b []byte) { b[24] = 3 }, "payload offset": func(b []byte) { be.PutUint32(b[28:], 1) },
		"encrypted": func(b []byte) { be.PutUint16(b[54:], 1) },
	} {
		t.Run(name, func(t *testing.T) {
			b := archiveSample()
			mutate(b)
			if name != "catalog CRC" {
				be.PutUint32(b[14:], ^crc32.ChecksumIEEE(b[18:]))
			}
			if _, err := Open(&starfile.Bytes{Data: b}, 1000, 1<<20); err == nil {
				t.Fatal("accepted malformed archive")
			}
		})
	}
}

func FuzzArchiveBounded(f *testing.F) {
	f.Add(archiveSample())
	f.Fuzz(func(t *testing.T, b []byte) {
		a, err := Open(&starfile.Bytes{Data: b}, 1000, 1<<16)
		if err != nil {
			return
		}
		var total int64
		for _, e := range a.Entries {
			if e.Directory {
				continue
			}
			total += e.Data.Size() + e.Resource.Size()
		}
		if total > 1<<16 {
			t.Fatal("decoded bytes escaped limit")
		}
	})
}
func FuzzForkBounded(f *testing.F) {
	f.Add([]byte{'A', 0x81, 0x82, 4}, uint16(4), false)
	w := testBits{}
	start := w.header()
	w.literal('A')
	w.match(3, 1)
	w.padding(start)
	f.Add(w.data, uint16(4), true)
	f.Fuzz(func(t *testing.T, b []byte, size uint16, lzh bool) {
		got, err := decode(b, int(size), lzh)
		if err == nil && len(got) != int(size) {
			t.Fatal("wrong decoded length")
		}
	})
}
