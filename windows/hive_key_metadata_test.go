package windows

import (
	"encoding/binary"
	"go.starlark.net/starlark"
	"testing"
)

func TestHiveKeyMetadataAttributes(t *testing.T) {
	root := newRegistryTree("ROOT")
	node := ensureRegistryKey(root, "/Metadata")
	node.class = utf16Bytes("nonempty Ω")
	data, err := buildRegistryHive(root)
	if err != nil {
		t.Fatal(err)
	}
	hive, err := newRegistryHive(testHiveFile(data))
	if err != nil {
		t.Fatal(err)
	}
	key, err := hive.lookup("/Metadata")
	if err != nil {
		t.Fatal(err)
	}
	const timestamp = uint64(0x01dc123456789abc)
	// REGF 1.5 cell offsets include the four-byte cell header.
	binary.LittleEndian.PutUint64(data[0x1000+key.cell+4+4:], timestamp)
	hive, err = newRegistryHive(testHiveFile(data))
	if err != nil {
		t.Fatal(err)
	}
	key, err = hive.lookup("/Metadata")
	if err != nil {
		t.Fatal(err)
	}
	view := &registryKey{hive: hive, key: key, path: "/Metadata", parts: []string{"Metadata"}}
	cls, err := view.Attr("class_bytes")
	if err != nil || cls != starlark.Bytes(node.class) {
		t.Fatalf("class %v: %v", cls, err)
	}
	stamp, err := view.Attr("last_write_time")
	if err != nil || stamp.String() != starlark.MakeUint64(timestamp).String() {
		t.Fatalf("timestamp %v: %v", stamp, err)
	}
	portable := portableKey(key)
	if portable.LastWriteTime != timestamp {
		t.Fatalf("portable timestamp %#x", portable.LastWriteTime)
	}
}
