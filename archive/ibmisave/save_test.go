package ibmisave

import (
	"bytes"
	"encoding/binary"
	"github.com/tinyrange/trex/auto"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
	"testing"
)

func fixture() []byte {
	b := make([]byte, 3*pageSize)
	h := b[:pageSize]
	be := binary.BigEndian
	be.PutUint32(h, 0xffffffff)
	copy(h[4:34], bytes.Repeat([]byte{0x40}, 30))
	copy(h[4:], catalogName)
	be.PutUint16(h[34:], 0x19db)
	be.PutUint16(h[0x52:], 0x4705)
	be.PutUint16(h[0x54:], 0x4705)
	copy(h[0x96:], descriptor)
	be.PutUint32(h[0xcc:], 24)
	be.PutUint32(h[0xd4:], 48)
	be.PutUint32(h[0x64:], 1)
	be.PutUint64(h[0x108:], 0xf000000000001280)
	be.PutUint32(h[0x280:], 16384)
	be.PutUint32(h[0x284:], 4096)
	be.PutUint64(h[0x288:], 0x123456789abcdef0)
	copy(b[pageSize:], "stored section")
	copy(b[2*pageSize:], "opaque trailer")
	return b
}

func TestGroupsSectionsAndBorrowedBytes(t *testing.T) {
	b := fixture()
	b = append(b, bytes.Repeat([]byte{0x40}, pageSize)...)
	b = append(b, fixture()...)
	f := &starfile.Bytes{Data: b}
	a, err := Open(f, 10)
	if err != nil {
		t.Fatal(err)
	}
	if a.Groups != 2 || len(a.Objects) != 2 || len(a.Padding) != 1 {
		t.Fatal(a)
	}
	o := a.Objects[1]
	if o.Name != "QSRDSSPC.1" || o.Offset != 4*pageSize || o.Trailer.Size() != pageSize || o.Sections[0].LogicalSize != 16384 || o.Sections[0].Address != 0x123456789abcdef0 {
		t.Fatal(o)
	}
	b[5*pageSize] = 'X'
	p := make([]byte, 1)
	if _, err = o.Sections[0].Data.ReadAt(p, 0); err != nil || p[0] != 'X' {
		t.Fatal(p, err)
	}
	if _, err := Builtin(nil, nil, starlark.Tuple{f}, nil); err != nil {
		t.Fatal(err)
	}
	n := auto.Open(f, "QUSRSYS", auto.Options{})
	header, err := n.Resolve("save2/QSRDSSPC.1/descriptor.bin")
	if err != nil {
		t.Fatal(err)
	}
	if m, err := header.Metadata(); err != nil || m.Container {
		t.Fatal("raw descriptor redetected", m, err)
	}
	child, err := n.Resolve("save2/QSRDSSPC.1/trailer.bin")
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 14)
	_, err = child.Reader().ReadAt(data, 0)
	if err != nil || string(data) != "opaque trailer" {
		t.Fatal(string(data), err)
	}
}

func TestMalformed(t *testing.T) {
	for name, edit := range map[string]func([]byte){
		"signature": func(b []byte) { b[0] = 0 },
		"release":   func(b []byte) { b[0x52] = 0 },
		"extent":    func(b []byte) { binary.BigEndian.PutUint32(b[0xcc:], 32) },
		"table":     func(b []byte) { binary.BigEndian.PutUint64(b[0x108:], 4095) },
		"count":     func(b []byte) { binary.BigEndian.PutUint32(b[0x64:], 1000) },
		"section":   func(b []byte) { binary.BigEndian.PutUint32(b[0x284:], 16384) },
	} {
		t.Run(name, func(t *testing.T) {
			b := fixture()
			edit(b)
			if _, err := Open(&starfile.Bytes{Data: b}, 100); err == nil {
				t.Fatal("accepted malformed stream")
			}
		})
	}
	if _, err := Open(&starfile.Bytes{Data: fixture()}, 0); err == nil {
		t.Fatal("accepted zero budget")
	}
	if _, err := Open(&starfile.Bytes{Data: fixture()[:pageSize+1]}, 10); err == nil {
		t.Fatal("accepted partial page")
	}
}

func TestDuplicateNames(t *testing.T) {
	b := append(fixture(), fixture()...)
	n := auto.Open(&starfile.Bytes{Data: b}, "", auto.Options{})
	for _, p := range []string{"save1/QSRDSSPC.1/occurrence1/stored.bin", "save1/QSRDSSPC.1/occurrence2/stored.bin"} {
		if _, err := n.Resolve(p); err != nil {
			t.Fatal(err)
		}
	}
}
