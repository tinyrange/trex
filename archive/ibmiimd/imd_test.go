package ibmiimd

import (
	"encoding/binary"
	"testing"

	"github.com/tinyrange/trex/auto"
	starfile "github.com/tinyrange/trex/storage/star"
)

func fixture() []byte {
	b := make([]byte, 70*1024)
	copy(b, magic)
	binary.BigEndian.PutUint32(b[4096:], 0x80000002)
	copy(b[4100:], []byte{0xd3, 0xc9, 0xc4, 0xc4, 0xc9, 0xd9, 0x40, 0x40})
	for i := 0; i < 2; i++ {
		row := b[4128+i*32 : 4160+i*32]
		binary.BigEndian.PutUint32(row, uint32(0x80100001+i))
		binary.BigEndian.PutUint32(row[4:], uint32(128+i*2))
		binary.BigEndian.PutUint32(row[8:], 2)
		binary.BigEndian.PutUint32(row[12:], uint32(i)*0x80000000)
		binary.BigEndian.PutUint64(row[16:], 0xffffffff10000000+uint64(i)*1024)
		copy(b[(128+i*2)*512:], []byte{byte(0xa0 + i), 0x17, 0x33})
	}
	copy(b[4192:], endMagic)
	return b
}

func TestBorrowedComponentViewsAndAuto(t *testing.T) {
	source := &starfile.Bytes{Data: fixture()}
	image, err := Open(source, 10, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if len(image.Entries) != 2 || image.StoredBytes != 2048 || image.DecodingComplete {
		t.Fatal(image)
	}
	data, err := starfile.ReadAll(image.Entries[1].Data)
	if err != nil || len(data) != 1024 || data[0] != 0xa1 {
		t.Fatal(len(data), err)
	}
	if image.Entries[1].DeclaredAddress != 0xffffffff10000400 || image.Entries[1].Flags != 0x80000000 {
		t.Fatal(image.Entries[1])
	}
	result, err := auto.Identify(source, auto.Options{})
	if err != nil || result.Format != "ibmi_imd" {
		t.Fatal(result, err)
	}
	root, err := result.View.Entries()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range root {
		if e.Name == "components" {
			children, err := e.View.Entries()
			if err != nil || len(children) != 2 || children[0].Attributes["decoding_complete"] != false {
				t.Fatal(children, err)
			}
			return
		}
	}
	t.Fatal("missing automatic component view")
}

func TestMalformedDirectoryAndBudgets(t *testing.T) {
	be := binary.BigEndian
	for name, mutate := range map[string]func([]byte){
		"huge count":        func(b []byte) { be.PutUint32(b[4096:], 0x80ffffff) },
		"marker":            func(b []byte) { b[4192] = 0 },
		"duplicate":         func(b []byte) { be.PutUint32(b[4160:], 0x80100001) },
		"overlap":           func(b []byte) { be.PutUint32(b[4164:], 128) },
		"empty":             func(b []byte) { be.PutUint32(b[4136:], 0) },
		"directory overlap": func(b []byte) { be.PutUint32(b[4132:], 8) },
		"outside":           func(b []byte) { be.PutUint32(b[4132:], 0xffffffff) },
		"length outside":    func(b []byte) { be.PutUint32(b[4136:], 0xffffffff) },
	} {
		t.Run(name, func(t *testing.T) {
			b := fixture()
			mutate(b)
			if _, err := Open(&starfile.Bytes{Data: b}, 1000, 1<<20); err == nil {
				t.Fatal("accepted malformed directory")
			}
		})
	}
	source := &starfile.Bytes{Data: fixture()}
	if _, err := Open(source, 1, 2048); err == nil {
		t.Fatal("entry budget ignored")
	}
	if _, err := Open(source, 2, 2047); err == nil {
		t.Fatal("byte budget ignored")
	}
	if _, err := Open(&starfile.Bytes{Data: fixture()[:4193]}, 10, 2048); err == nil {
		t.Fatal("truncated table accepted")
	}
}
