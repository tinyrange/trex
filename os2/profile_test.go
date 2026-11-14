package os2

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func TestProfileLinkedRecords(t *testing.T) {
	entries := []Entry{{"A", "first", []byte("old")}, {"B", "binary", []byte{0, 255, 1}}, {"A", "second", nil}, {"A", "first", []byte("new\x00")}, {"a", "first", []byte("case")}}
	b, err := Profile(entries)
	if err != nil {
		t.Fatal(err)
	}
	le := binary.LittleEndian
	if le.Uint32(b) != 0xffffffff || int(le.Uint32(b[8:])) != len(b) {
		t.Fatal("bad header")
	}
	var got []Entry
	for app := le.Uint32(b[4:]); app != 0; app = le.Uint32(b[app:]) {
		n := le.Uint16(b[app+12:])
		off := le.Uint32(b[app+16:])
		if n != le.Uint16(b[app+14:]) || b[off+uint32(n)-1] != 0 {
			t.Fatal("application name extent")
		}
		name := string(b[off : off+uint32(n)-1])
		for key := le.Uint32(b[app+4:]); key != 0; key = le.Uint32(b[key:]) {
			n := le.Uint16(b[key+8:])
			off := le.Uint32(b[key+12:])
			size := le.Uint16(b[key+16:])
			data := le.Uint32(b[key+20:])
			if n != le.Uint16(b[key+10:]) || size != le.Uint16(b[key+18:]) || b[off+uint32(n)-1] != 0 {
				t.Fatal("key extent")
			}
			got = append(got, Entry{name, string(b[off : off+uint32(n)-1]), b[data : data+uint32(size)]})
		}
	}
	want := []Entry{entries[3], entries[2], entries[1], entries[4]}
	if len(got) != len(want) {
		t.Fatal(got)
	}
	for i, e := range want {
		if got[i].Application != e.Application || got[i].Key != e.Key || !bytes.Equal(got[i].Data, e.Data) {
			t.Fatalf("record %d: %+v", i, got[i])
		}
	}
	empty, err := Profile(nil)
	if err != nil || len(empty) != 20 || le.Uint32(empty[4:]) != 0 {
		t.Fatal("empty profile")
	}
}
func TestProfileRejectsUnrepresentableEntries(t *testing.T) {
	for _, e := range []Entry{{"", "x", nil}, {"A", "x\x00y", nil}, {"A", strings.Repeat("x", 65535), nil}, {"A", "k", make([]byte, 65536)}} {
		if _, err := Profile([]Entry{e}); err == nil {
			t.Fatal("accepted invalid entry")
		}
	}
}
