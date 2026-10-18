package ese

import (
	"encoding/binary"
	"testing"
)

func TestSmallPageTaggedOffsets(t *testing.T) {
	for _, size := range []int64{2048, 4096, 8192} {
		d := &Database{info: Info{Version: 0x620, Revision: 20, PageSize: size}}
		// Three directory entries: flagged binary, unflagged text, explicit NULL.
		data := []byte{0, 1, 12, 0x40, 1, 1, 15, 0, 2, 1, 18, 0x20, 1, 0xfe, 0xff, 'a', 'b', 'c'}
		v, err := d.decodeTaggedValues(data)
		if err != nil {
			t.Fatal(err)
		}
		if len(v) != 2 || v[256].flags != 1 || string(v[256].data) != string([]byte{0xfe, 0xff}) || string(v[257].data) != "abc" {
			t.Fatalf("page %d: %#v", size, v)
		}
		for _, off := range []uint16{0x4003, 0x4014, 0x600c} {
			bad := append([]byte(nil), data...)
			binary.LittleEndian.PutUint16(bad[2:4], off)
			if _, err := d.decodeTaggedValues(bad); err == nil {
				t.Fatalf("accepted offset %x", off)
			}
		}
	}
}

func TestLargePageTaggedOffsetsKeepHighBits(t *testing.T) {
	d := &Database{info: Info{Version: 0x620, Revision: 20, PageSize: 32768}}
	// A second column above 16 KiB: bit 14 is an offset, not an info flag.
	data := make([]byte, 0x4003)
	copy(data, []byte{0, 1, 8, 0, 1, 1, 1, 0x40})
	data[8] = 1
	data[0x4001] = 1
	data[0x4002] = 0xab
	v, err := d.decodeTaggedValues(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(v[256].data) != 0x3ff8 || len(v[257].data) != 1 || v[257].data[0] != 0xab {
		t.Fatal("large-page offsets truncated")
	}
}
