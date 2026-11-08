package cab

import (
	"encoding/binary"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
	"testing"
)

func TestEntryPreservesRawCABMetadata(t *testing.T) {
	data := testCABIdentifiers([]string{"first", "second"})
	binary.LittleEndian.PutUint16(data[32:], 0x1234)
	binary.LittleEndian.PutUint16(data[34:], 7)
	binary.LittleEndian.PutUint16(data[54:], 0x5d41)
	binary.LittleEndian.PutUint16(data[56:], 0x7283)
	binary.LittleEndian.PutUint16(data[58:], 0x21)
	archive, err := Open(&starfile.Bytes{Data: data}, false)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := archive.Lookup("first")
	if err != nil {
		t.Fatal(err)
	}
	value, err := entry.Attr("cab_metadata")
	if err != nil {
		t.Fatal(err)
	}
	metadata := value.(*starlark.Dict)
	for name, expected := range map[string]int{"date": 0x5d41, "time": 0x7283, "attributes": 0x21, "folder": 0, "set_id": 0x1234, "cabinet": 7} {
		got, found, err := metadata.Get(starlark.String(name))
		if err != nil || !found || got.String() != starlark.MakeInt(expected).String() {
			t.Fatalf("%s = %v (%v), want %d", name, got, err, expected)
		}
	}
	if err := metadata.SetKey(starlark.String("date"), starlark.MakeInt(0)); err == nil {
		t.Fatal("metadata must be immutable")
	}
}
