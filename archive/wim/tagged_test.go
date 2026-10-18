package wim

import (
	"encoding/binary"
	"testing"
)

func TestWIMTaggedItems(t *testing.T) {
	data := make([]byte, 40)
	binary.LittleEndian.PutUint32(data, 2)
	binary.LittleEndian.PutUint32(data[4:], 3)
	copy(data[8:], "abc")
	binary.LittleEndian.PutUint32(data[16:], 0xdeadbeef)
	binary.LittleEndian.PutUint32(data[20:], 1)
	data[24] = 7
	binary.LittleEndian.PutUint32(data[32:], 2)
	items, err := parseWIMTaggedItems(data)
	if err != nil || len(items) != 3 {
		t.Fatalf("items=%v err=%v", items, err)
	}
	if items[0].tag != 2 || string(items[0].data) != "abc" || items[1].tag != 0xdeadbeef || len(items[2].data) != 0 {
		t.Fatalf("items=%v", items)
	}
	for _, bad := range [][]byte{data[:3], data[:10], data[:17], {2, 0, 0, 0, 255, 255, 255, 255}} {
		if _, err := parseWIMTaggedItems(bad); err == nil {
			t.Errorf("accepted truncated/oversized extension: %x", bad)
		}
	}
}

func TestWIMEntryTaggedItemsAfterNames(t *testing.T) {
	// Nonzero entry offset and two terminated UTF-16 names. Tagged data must
	// begin at the dentry-relative alignment, not the containing buffer's.
	const off = 3
	const extra = 112
	data := make([]byte, off+extra+16)
	e := data[off:]
	binary.LittleEndian.PutUint64(e, uint64(len(e)))
	binary.LittleEndian.PutUint16(e[98:], 2)
	binary.LittleEndian.PutUint16(e[100:], 2)
	e[102] = 'x'
	e[106] = 'X'
	binary.LittleEndian.PutUint32(e[extra:], 3)
	binary.LittleEndian.PutUint32(e[extra+4:], 3)
	copy(e[extra+8:], "EA!")
	entry, err := parseWIMEntry(data, off, "/image1")
	if err != nil {
		t.Fatal(err)
	}
	if len(entry.taggedItems) != 1 || entry.taggedItems[0].tag != 3 || string(entry.taggedItems[0].data) != "EA!" {
		t.Fatalf("tags=%v", entry.taggedItems)
	}
	file := (&Archive{}).newFile(entry)
	metadata, err := file.Attr("metadata")
	if err != nil {
		t.Fatal(err)
	}
	if metadata == nil {
		t.Fatal("missing metadata")
	}
	binary.LittleEndian.PutUint32(e[extra+4:], 100)
	if _, err := parseWIMEntry(data, off, "/image1"); err == nil {
		t.Fatal("accepted extension past dentry")
	}
}
