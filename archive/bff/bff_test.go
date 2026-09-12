package bff

import (
	"bytes"
	"encoding/binary"
	"github.com/tinyrange/trex/auto"
	starfile "github.com/tinyrange/trex/storage/star"
	"testing"
)

func seal(h []byte) { binary.LittleEndian.PutUint16(h[4:], HeaderChecksum(h)) }
func fixture(packed bool) []byte {
	le := binary.LittleEndian
	volume := make([]byte, 72)
	volume[0] = 9
	le.PutUint16(volume[2:], ordinaryMagic)
	le.PutUint16(volume[6:], 1)
	le.PutUint16(volume[68:], 100)
	seal(volume)
	h := make([]byte, 72)
	h[0] = 9
	h[1] = extendedNameRecord
	le.PutUint16(h[2:], ordinaryMagic)
	le.PutUint16(h[6:], 1)
	le.PutUint32(h[8:], 42)
	le.PutUint32(h[12:], 0100644)
	le.PutUint32(h[24:], 4)
	le.PutUint32(h[56:], 4)
	copy(h[64:], "file")
	data := []byte("ABBA")
	if packed {
		le.PutUint16(h[2:], packedMagic)
		data = []byte{2, 1, 0, 'A', 'B', 0x85}
		le.PutUint32(h[56:], uint32(len(data)))
	}
	seal(h)
	security := make([]byte, 40)
	le.PutUint32(security, 2)
	le.PutUint32(security[4:], 2)
	le.PutUint32(security[8:], 16)
	le.PutUint32(security[24:], 16)
	b := append(volume, h...)
	b = append(b, security...)
	b = append(b, data...)
	for len(b)%8 != 0 {
		b = append(b, 0)
	}
	end := []byte{1, 7, 0x6b, 0xea, 0, 0, 0, 0}
	seal(end)
	return append(b, end...)
}

func TestReadStoredAndPacked(t *testing.T) {
	if HeaderChecksum([]byte{1, 7, 0x6b, 0xea, 0, 0, 0, 0}) != 2690 {
		t.Fatal("checksum byte transform")
	}
	for _, packed := range []bool{false, true} {
		b := fixture(packed)
		f := &starfile.Bytes{Data: b}
		a, err := Open(f, 1, 4)
		if err != nil {
			t.Fatal(err)
		}
		if len(a.Entries) != 1 || a.Entries[0].Path != "/file" || a.Entries[0].Packed != packed || a.Entries[0].Inode != 42 {
			t.Fatal(a)
		}
		e := a.Entries[0]
		data, err := starfile.ReadAll(e.Data)
		if err != nil || string(data) != "ABBA" {
			t.Fatal(data, err)
		}
		if e.ACL.Size() != 16 || e.PCL.Size() != 16 {
			t.Fatal("security lost")
		}
		if !packed {
			b[184] = 'Z'
			data, _ := starfile.ReadAll(e.Data)
			if data[0] != 'Z' {
				t.Fatal("copied stored data")
			}
		}
		node, err := auto.Open(f, "", auto.Options{}).Resolve("file")
		if err != nil || node.Reader().Size() != 4 {
			t.Fatal(node, err)
		}
	}
}

func TestRejectCorruption(t *testing.T) {
	for name, mutate := range map[string]func([]byte){
		"checksum":        func(b []byte) { b[80] ^= 1 },
		"length":          func(b []byte) { b[72] = 0 },
		"record type":     func(b []byte) { b[73] = 9; seal(b[72:144]) },
		"size":            func(b []byte) { binary.LittleEndian.PutUint32(b[72+56:], 10000); seal(b[72:144]) },
		"security":        func(b []byte) { binary.LittleEndian.PutUint32(b[144:], 10000) },
		"security length": func(b []byte) { binary.LittleEndian.PutUint32(b[152:], 17) },
		"unsafe path":     func(b []byte) { copy(b[136:], "../x\x00"); seal(b[72:144]) },
		"name":            func(b []byte) { copy(b[136:144], "abcdefgh"); seal(b[72:144]) },
		"continuation":    func(b []byte) { binary.LittleEndian.PutUint16(b[6:], 2); seal(b[:72]) },
	} {
		t.Run(name, func(t *testing.T) {
			b := fixture(false)
			mutate(b)
			if _, err := Open(&starfile.Bytes{Data: b}, 10, 100); err == nil {
				t.Fatal("accepted corrupt input")
			}
		})
	}
	b := fixture(true)
	if _, err := Open(&starfile.Bytes{Data: b}, 1, 3); err == nil {
		t.Fatal("decoded limit ignored")
	}
	for _, n := range []int{7, 71, 80, 143, 151, 183, len(b) - 1} {
		if _, err := Open(&starfile.Bytes{Data: b[:n]}, 10, 100); err == nil {
			t.Fatal("accepted truncation", n)
		}
	}
	bad := bytes.Clone(b)
	bad[189] ^= 1
	if _, err := Open(&starfile.Bytes{Data: bad}, 10, 100); err == nil {
		t.Fatal("accepted bad packed padding")
	}
}

func TestPhysicalTail(t *testing.T) {
	b := fixture(false)
	b = append(b, bytes.Repeat([]byte{0xa5}, distributionBlock-len(b))...)
	a, err := Open(&starfile.Bytes{Data: b}, 10, 100)
	if err != nil || a.Trailer.Size() == 0 {
		t.Fatal(a, err)
	}
	b = append(b, 0)
	if _, err := Open(&starfile.Bytes{Data: b}, 10, 100); err == nil {
		t.Fatal("accepted unframed tail")
	}
}
