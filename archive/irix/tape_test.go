package irix

import (
	"encoding/binary"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
)

func tapeChecksum(data []byte) {
	be := binary.BigEndian
	be.PutUint32(data[4:], 0)
	var sum uint32
	for off := 0; off < 512; off += 4 {
		sum += be.Uint32(data[off:])
	}
	be.PutUint32(data[4:], -sum)
}

func tapeFixture() *starfile.Bytes {
	data := make([]byte, 1024)
	binary.BigEndian.PutUint32(data, 0xaced1234)
	copy(data[32:], "sash")
	binary.BigEndian.PutUint32(data[48:], 1)
	binary.BigEndian.PutUint32(data[52:], 4)
	copy(data[512:], "data")
	tapeChecksum(data)
	return &starfile.Bytes{Data: data}
}

func TestStandaloneTape(t *testing.T) {
	f := tapeFixture()
	entries, err := OpenTape(f)
	if err != nil || len(entries) != 1 || entries[0].Name != "sash" || entries[0].Offset != 512 {
		t.Fatalf("%v %v", entries, err)
	}
	got, err := starfile.ReadAll(entries[0].Data)
	if err != nil || string(got) != "data" {
		t.Fatalf("%q %v", got, err)
	}
	for _, change := range []func([]byte){
		func(b []byte) { b[4] ^= 1 },
		func(b []byte) { binary.BigEndian.PutUint32(b[48:], 2); tapeChecksum(b) },
		func(b []byte) { binary.BigEndian.PutUint32(b[52:], 513); tapeChecksum(b) },
		func(b []byte) { copy(b[56:80], b[32:56]); b[56] = 'x'; tapeChecksum(b) },
	} {
		bad := tapeFixture()
		change(bad.Data)
		if _, err := OpenTape(bad); err == nil {
			t.Fatal("accepted corrupt tape directory")
		}
	}
}
