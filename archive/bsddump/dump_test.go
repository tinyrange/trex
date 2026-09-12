package bsddump

import (
	"encoding/binary"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
)

func seal(h []byte, order binary.ByteOrder) {
	order.PutUint32(h[28:], 0)
	var sum uint32
	for i := 0; i < 1024; i += 4 {
		sum += order.Uint32(h[i:])
	}
	order.PutUint32(h[28:], 84446-sum)
}

// A full dump with a sparse file, continuation, hard link and repeated END.
func fixture(order binary.ByteOrder) []byte {
	b := make([]byte, 12*1024)
	header := func(block int, kind, ino uint32, flags []byte) []byte {
		h := b[block*1024 : (block+1)*1024]
		for off, value := range map[int]uint32{0: kind, 4: 123, 12: 1, 16: uint32(block), 20: ino, 24: 60012, 160: uint32(len(flags))} {
			order.PutUint32(h[off:], value)
		}
		copy(h[164:], flags)
		return h
	}
	header(0, 1, 0, nil)
	header(1, 6, 0, []byte{0})
	b[2*1024] = 6
	header(3, 3, 0, []byte{0})
	b[4*1024] = 6
	h := header(5, 2, 2, []byte{1})
	order.PutUint16(h[32:], 0x41ed)
	order.PutUint16(h[34:], 2)
	order.PutUint64(h[40:], 512)
	dir := b[6*1024:]
	for _, e := range []struct {
		off, length int
		ino         uint32
		name        string
	}{{0, 12, 2, "."}, {12, 12, 2, ".."}, {24, 16, 3, "file"}, {40, 472, 3, "alias"}} {
		order.PutUint32(dir[e.off:], e.ino)
		order.PutUint16(dir[e.off+4:], uint16(e.length))
		order.PutUint16(dir[e.off+6:], uint16(len(e.name)))
		copy(dir[e.off+8:], e.name)
	}
	h = header(7, 2, 3, []byte{0})
	order.PutUint16(h[32:], 0x81a4)
	order.PutUint16(h[34:], 2)
	order.PutUint16(h[36:], 42)
	order.PutUint64(h[40:], 1027)
	next := header(8, 4, 3, []byte{1})
	copy(next[32:160], h[32:160])
	copy(b[9*1024:], "abc")
	header(10, 5, 0, nil)
	header(11, 5, 0, nil)
	for _, block := range []int{0, 1, 3, 5, 7, 8, 10, 11} {
		seal(b[block*1024:(block+1)*1024], order)
	}
	return b
}

func TestFullDump(t *testing.T) {
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		a, err := Open(&starfile.Bytes{Data: fixture(order)}, 10, 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		if len(a.Entries) != 3 || a.Date != 123 || a.Entries[1].Path != "/file" || a.Entries[2].Path != "/alias" || a.Entries[1].UID != 42 {
			t.Fatal(a)
		}
		if a.Entries[1].Data != a.Entries[2].Data {
			t.Fatal("hard link identity lost")
		}
		data, err := starfile.ReadAll(a.Entries[1].Data)
		if err != nil || len(data) != 1027 || string(data[1024:]) != "abc" {
			t.Fatal(len(data), err)
		}
		for _, v := range data[:1024] {
			if v != 0 {
				t.Fatal("nonzero hole")
			}
		}
	}
}

func TestMalformed(t *testing.T) {
	for name, mutate := range map[string]func([]byte){
		"missing map bit":   func(b []byte) { b[4*1024] = 2 },
		"extra map bit":     func(b []byte) { b[4*1024] |= 8 },
		"unallocated inode": func(b []byte) { b[2*1024] = 2 },
		"checksum":          func(b []byte) { b[28]++ },
		"incremental":       func(b []byte) { binary.LittleEndian.PutUint32(b[8:], 1); seal(b[:1024], binary.LittleEndian) },
		"continuation": func(b []byte) {
			binary.LittleEndian.PutUint32(b[8*1024+20:], 4)
			seal(b[8*1024:9*1024], binary.LittleEndian)
		},
		"address": func(b []byte) { b[7*1024+164] = 2; seal(b[7*1024:8*1024], binary.LittleEndian) },
		"count": func(b []byte) {
			binary.LittleEndian.PutUint32(b[7*1024+160:], 513)
			seal(b[7*1024:8*1024], binary.LittleEndian)
		},
		"missing inode": func(b []byte) { binary.LittleEndian.PutUint32(b[6*1024+24:], 4) },
		"dot":           func(b []byte) { binary.LittleEndian.PutUint32(b[6*1024+12:], 3) },
		"tape position": func(b []byte) {
			binary.LittleEndian.PutUint32(b[8*1024+16:], 7)
			seal(b[8*1024:9*1024], binary.LittleEndian)
		},
	} {
		t.Run(name, func(t *testing.T) {
			b := fixture(binary.LittleEndian)
			mutate(b)
			if _, err := Open(&starfile.Bytes{Data: b}, 10, 1<<20); err == nil {
				t.Fatal("accepted malformed dump")
			}
		})
	}
	b := fixture(binary.LittleEndian)
	for _, length := range []int{0, 1023, 1024, 6 * 1024, 9 * 1024, 10 * 1024, len(b) - 1} {
		if _, err := Open(&starfile.Bytes{Data: b[:length]}, 10, 1<<20); err == nil {
			t.Fatalf("accepted truncated length %d", length)
		}
	}
	if _, err := Open(&starfile.Bytes{Data: b}, 2, 1<<20); err == nil {
		t.Fatal("entry limit")
	}
	if _, err := Open(&starfile.Bytes{Data: b}, 10, int64(len(b)-1)); err == nil {
		t.Fatal("byte limit")
	}
}

func FuzzOpen(f *testing.F) {
	f.Add(fixture(binary.LittleEndian))
	f.Add(fixture(binary.BigEndian))
	f.Fuzz(func(t *testing.T, b []byte) {
		a, err := Open(&starfile.Bytes{Data: b}, 100, 1<<20)
		if err != nil {
			return
		}
		for _, e := range a.Entries {
			if _, err := starfile.ReadAll(e.Data); err != nil {
				t.Fatal(err)
			}
		}
	})
}
