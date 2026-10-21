package xcoff

import (
	"encoding/binary"
	"testing"

	"github.com/tinyrange/trex/auto"
	starfile "github.com/tinyrange/trex/storage/star"
)

func fixture() []byte {
	b := make([]byte, 256)
	be := binary.BigEndian
	be.PutUint16(b, 0x01df)
	be.PutUint16(b[2:], 2)
	be.PutUint16(b[16:], 72)
	be.PutUint16(b[20:], 0x010b)
	be.PutUint32(b[36:], 0xffffffff)
	copy(b[92:], ".text")
	be.PutUint32(b[104:], 0x1000)
	be.PutUint32(b[108:], 8)
	be.PutUint32(b[112:], 192)
	be.PutUint32(b[128:], 0x20)
	copy(b[132:], ".bss")
	be.PutUint32(b[144:], 0x2000)
	be.PutUint32(b[148:], 4096)
	be.PutUint32(b[168:], 0x80)
	copy(b[192:], "textdata")
	return b
}

func TestSectionsNoFabricatedBSSOrEntry(t *testing.T) {
	source := &starfile.Bytes{Data: fixture()}
	f, err := Open(source, 8)
	if err != nil {
		t.Fatal(err)
	}
	if f.HasEntry || f.EntryPoint != 0xffffffff || len(f.Sections) != 2 || f.Sections[1].Stored != nil {
		t.Fatal(f)
	}
	text, err := starfile.ReadAll(f.Sections[0].Stored)
	if err != nil || string(text) != "textdata" {
		t.Fatal(string(text), err)
	}
	result, err := auto.Identify(source, auto.Options{})
	if err != nil || result.Format != "xcoff32" {
		t.Fatal(result, err)
	}
	entries, err := result.View.Entries()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name == "sections" {
			children, err := e.View.Entries()
			if err != nil || len(children) != 1 {
				t.Fatal(children, err)
			}
			return
		}
	}
	t.Fatal("missing section view")
}

func TestMalformedXCOFFBounds(t *testing.T) {
	be := binary.BigEndian
	for name, change := range map[string]func([]byte){
		"generation":                func(b []byte) { be.PutUint16(b, 0x01f7) },
		"section count":             func(b []byte) { be.PutUint16(b[2:], 0xffff) },
		"optional size":             func(b []byte) { be.PutUint16(b[16:], 0xffff) },
		"section outside":           func(b []byte) { be.PutUint32(b[112:], 0xfffffff0) },
		"section overlaps headers":  func(b []byte) { be.PutUint32(b[112:], 92) },
		"section size":              func(b []byte) { be.PutUint32(b[108:], 0xffffffff) },
		"unknown flags are not BSS": func(b []byte) { be.PutUint32(b[168:], 0xffffffff) },
		"initialized missing":       func(b []byte) { be.PutUint32(b[168:], 0x40) },
		"relocations":               func(b []byte) { be.PutUint16(b[124:], 2); be.PutUint32(b[116:], 250) },
		"symbols":                   func(b []byte) { be.PutUint32(b[8:], 240); be.PutUint32(b[12:], 1) },
		"overflow":                  func(b []byte) { be.PutUint16(b[124:], 0xffff) },
	} {
		t.Run(name, func(t *testing.T) {
			b := fixture()
			change(b)
			if _, err := Open(&starfile.Bytes{Data: b}, 8); err == nil {
				t.Fatal("accepted malformed XCOFF")
			}
		})
	}
	if _, err := Open(&starfile.Bytes{Data: fixture()}, 1); err == nil {
		t.Fatal("section budget ignored")
	}
}
