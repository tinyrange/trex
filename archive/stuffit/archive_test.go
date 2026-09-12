package stuffit

import (
	"bytes"
	"encoding/binary"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
)

type bitWriter struct {
	data []byte
	pos  int
}

func (w *bitWriter) put(v uint32, n int) {
	for i := 0; i < n; i++ {
		if w.pos%8 == 0 {
			w.data = append(w.data, 0)
		}
		w.data[w.pos/8] |= byte(v>>uint(i)&1) << uint(w.pos%8)
		w.pos++
	}
}
func (w *bitWriter) meta(symbol int) { w.put(uint32(metaCodes[symbol]), metaCodeLengths[symbol]) }
func (w *bitWriter) symbol(h huffman13, symbol int) {
	for n, m := range h.codes {
		for c, s := range m {
			if s == symbol {
				for i := n - 1; i >= 0; i-- {
					w.put(c>>uint(i)&1, 1)
				}
				return
			}
		}
	}
	panic("missing test symbol")
}
func fixed13(selector int, values []int) []byte {
	w := bitWriter{}
	w.put(uint32(selector<<4), 8)
	current := 0
	for _, s := range values {
		h, _ := makeCode13(predefined13[selector-1][current])
		w.symbol(h, s)
		if s < 256 {
			current = 0
		} else {
			current = 1
		}
	}
	return w.data
}
func TestFixedLiteralTables(t *testing.T) {
	for selector := 1; selector <= 5; selector++ {
		if len(predefined13[selector-1][0]) != 321 || len(predefined13[selector-1][1]) != 321 {
			t.Fatal("table lengths")
		}
		input := fixed13(selector, []int{'A', 'B', 'C', 320})
		got, err := decode13(input, 3)
		if err != nil || string(got) != "ABC" {
			t.Fatalf("table%d: %q %v", selector, got, err)
		}
		if _, err := decode13(input, 2); err == nil {
			t.Fatal("ignored output bound")
		}
		if _, err := decode13(append(append([]byte{}, input...), 1), 3); err == nil {
			t.Fatal("accepted trailing bytes")
		}
	}
}
func TestMatchAndTableSwitch(t *testing.T) {
	w := bitWriter{}
	w.put(0x10, 8)
	a, _ := makeCode13(predefined13[0][0])
	b, _ := makeCode13(predefined13[0][1])
	d, _ := makeCode13(predefined13[0][2])
	w.symbol(a, 'A')
	w.symbol(a, 256)
	w.symbol(d, 0)
	w.symbol(b, 318)
	w.put(0, 10)
	w.symbol(d, 0)
	w.symbol(b, 320)
	got, err := decode13(w.data, 69)
	if err != nil || !bytes.Equal(got, bytes.Repeat([]byte{'A'}, 69)) {
		t.Fatalf("size%d %v", len(got), err)
	}
}
func TestDynamicTables(t *testing.T) {
	w := bitWriter{}
	w.put(8, 8) // Shared literal table, ten offset symbols.
	for i := 0; i < 321; i++ {
		if i == 'A' || i == 320 {
			w.meta(0)
		} else {
			w.meta(31)
		}
	}
	for i := 0; i < 10; i++ {
		if i == 0 {
			w.meta(0)
		} else {
			w.meta(31)
		}
	}
	// Only A and end-of-stream have codes: 0 and 1, respectively.
	w.put(0, 1)
	w.put(1, 1)
	got, err := decode13(w.data, 1)
	if err != nil || string(got) != "A" {
		t.Fatalf("%q %v", got, err)
	}
	for n := 0; n < len(w.data); n++ {
		if _, err := decode13(w.data[:n], 1); err == nil {
			t.Fatalf("accepted truncation%d", n)
		}
	}
}
func TestMetaLengthRuns(t *testing.T) {
	w := bitWriter{}
	w.meta(4)
	w.meta(32)
	w.meta(33)
	w.meta(34)
	w.put(1, 1)
	w.meta(35)
	w.put(0, 3)
	w.meta(36)
	w.put(0, 6)
	r := bitReader{data: w.data}
	got, err := readLengths13(&r, 19)
	if err != nil || len(got) != 19 || got[0] != 5 || got[1] != 6 {
		t.Fatalf("%v %v", got, err)
	}
	for _, n := range got[2:] {
		if n != 5 {
			t.Fatal(got)
		}
	}
	r = bitReader{data: w.data}
	if _, err := readLengths13(&r, 18); err == nil {
		t.Fatal("accepted oversized run")
	}
	if _, err := makeCode13([]int{1, 1, 1}); err == nil {
		t.Fatal("accepted overfull tree")
	}
	if _, err := makeCode13([]int{33}); err == nil {
		t.Fatal("accepted long code")
	}
}
func fixture() []byte {
	be := binary.BigEndian
	b := make([]byte, 22)
	copy(b, "SIT!")
	be.PutUint16(b[4:], 1)
	copy(b[10:], "rLau")
	b[14] = 2
	h := make([]byte, 112)
	h[2] = 1
	h[3] = 'F'
	h[0] = 13
	copy(h[66:], "TEXTttxt")
	be.PutUint32(h[76:], 100)
	be.PutUint32(h[80:], 200)
	r := fixed13(1, []int{'R', 320})
	d := []byte("data")
	be.PutUint32(h[84:], 1)
	be.PutUint32(h[88:], 4)
	be.PutUint32(h[92:], uint32(len(r)))
	be.PutUint32(h[96:], 4)
	be.PutUint16(h[100:], crc16([]byte{'R'}))
	be.PutUint16(h[102:], crc16(d))
	be.PutUint16(h[110:], crc16(h[:110]))
	b = append(b, h...)
	b = append(b, r...)
	b = append(b, d...)
	be.PutUint32(b[6:], uint32(len(b)))
	return b
}
func TestArchive(t *testing.T) {
	if crc16([]byte("123456789")) != 0xbb3d {
		t.Fatal("CRC generation")
	}
	a, err := Open(&starfile.Bytes{Data: fixture()}, 1, 1024)
	if err != nil {
		t.Fatal(err)
	}
	e := a.Entries[0]
	r, _ := starfile.ReadAll(e.Resource)
	d, _ := starfile.ReadAll(e.Data)
	if e.Path != "/F" || string(r) != "R" || string(d) != "data" || e.Created != 100 || e.Modified != 200 {
		t.Fatalf("%+v %q %q", e, r, d)
	}
	if _, err := Open(&starfile.Bytes{Data: fixture()}, 1, 4); err == nil {
		t.Fatal("ignored size limit")
	}
	for _, offset := range []int{0, 10, 25, 130, 135, len(fixture()) - 1} {
		b := fixture()
		b[offset] ^= 1
		if _, err := Open(&starfile.Bytes{Data: b}, 10, 1024); err == nil {
			t.Fatalf("accepted damaged byte%d", offset)
		}
	}
}
func FuzzMethod13Bounded(f *testing.F) {
	f.Add(fixed13(1, []int{'A', 320}), uint16(1))
	f.Fuzz(func(t *testing.T, b []byte, size uint16) {
		got, err := decode13(b, int(size))
		if err == nil && len(got) != int(size) {
			t.Fatal("wrong length")
		}
	})
}

func TestEncoderPadding(t *testing.T) {
	input := fixed13(1, []int{'A', 320})
	padded := append([]byte{}, input...)
	for (len(padded)-1)%4 != 0 {
		padded = append(padded, 0)
	}
	if got, err := decode13(padded, 1); err != nil || string(got) != "A" {
		t.Fatalf("padding %x %q %v", padded, got, err)
	}
	padded = append(padded, 0, 0, 0, 0)
	if _, err := decode13(padded, 1); err == nil {
		t.Fatal("accepted extra zero word")
	}
}
func TestDirectories(t *testing.T) {
	be := binary.BigEndian
	file := fixture()
	marker := func(method byte, name string) []byte {
		b := make([]byte, 112)
		b[0], b[1] = method, method
		b[2] = byte(len(name))
		copy(b[3:], name)
		be.PutUint16(b[110:], crc16(b[:110]))
		return b
	}
	b := append([]byte{}, file[:22]...)
	b = append(b, marker(32, "D")...)
	b = append(b, file[22:]...)
	b = append(b, marker(33, "Root name")...)
	be.PutUint32(b[6:], uint32(len(b)))
	a, err := Open(&starfile.Bytes{Data: b}, 2, 1024)
	if err != nil || a.Entries[1].Path != "/D/F" {
		t.Fatalf("%+v %v", a, err)
	}
	bad := append([]byte{}, b[:len(b)-112]...)
	be.PutUint32(bad[6:], uint32(len(bad)))
	if _, err := Open(&starfile.Bytes{Data: bad}, 2, 1024); err == nil {
		t.Fatal("accepted missing directory end")
	}
	be.PutUint16(b[4:], 2)
	if _, err := Open(&starfile.Bytes{Data: b}, 2, 1024); err == nil {
		t.Fatal("accepted top-level count mismatch")
	}
}

func TestInstallerDirectoryRecords(t *testing.T) {
	b := append([]byte{}, fixture()[:22]...)
	copy(b, "STi2")
	for _, method := range []byte{32, 33, 32, 33} {
		h := make([]byte, 112)
		h[0], h[1], h[2], h[3] = method, method, 1, 'D'
		binary.BigEndian.PutUint16(h[110:], crc16(h[:110]))
		b = append(b, h...)
	}
	binary.BigEndian.PutUint32(b[6:], uint32(len(b)))
	a, err := Open(&starfile.Bytes{Data: b}, 2, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Entries) != 2 || a.Entries[0].Path != "/D" || a.Entries[1].Path != "/D" || a.DeclaredCount != 1 || a.TopLevelCount != 2 || a.RootCountVerified {
		t.Fatalf("lost installer records: %+v", a)
	}
	b[len(b)-1] ^= 1
	if _, err := Open(&starfile.Bytes{Data: b}, 2, 100); err == nil {
		t.Fatal("ignored header CRC")
	}
}
