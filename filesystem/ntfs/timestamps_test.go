package ntfs

import (
	"encoding/binary"
	"reflect"
	"testing"

	filesystemapi "github.com/tinyrange/trex/filesystem"
	"go.starlark.net/starlark"
)

func TestExplicitConstructionTimesReachBothNTFSMetadataForms(t *testing.T) {
	root := filesystemapi.New()
	root.PutFile("/new.cat", filesystemapi.FileRecord{Data: []byte("catalog"), Size: 7})
	root.PutFile("/old.cat", filesystemapi.FileRecord{Data: []byte("old"), Size: 3})
	if err := root.HardLink("/old.cat", "/alias.cat"); err != nil {
		t.Fatal(err)
	}
	if err := root.SetFileAttributes("/old.cat", 0x22); err != nil {
		t.Fatal(err)
	}
	const created = uint64(134324352000000000)
	const written = uint64(134324352123456789)
	const accessed = uint64(134324352234567890)
	if err := root.SetTimes("/new.cat", created, written, accessed); err != nil {
		t.Fatal(err)
	}
	// Replace an old link with a new object whose name sorts after its alias.
	// The old sibling must survive, and the new alias must carry source times.
	if err := root.HardLink("/new.cat", "/alias.cat"); err != nil {
		t.Fatal(err)
	}
	if err := root.SetFileAttributes("/alias.cat", 0x87); err != nil {
		t.Fatal(err)
	}
	before := root.Snapshot()
	if err := root.SetFileAttributes("/new.cat", 0x400); err == nil {
		t.Fatal("accepted a structural reparse flag as basic information")
	}
	if !reflect.DeepEqual(before, root.Snapshot()) {
		t.Fatal("invalid attributes mutated the tree")
	}
	image, err := buildNTFSImage(root, 64<<20, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	volume, err := newNTFSVolume(image)
	if err != nil {
		t.Fatal(err)
	}
	if volume.paths["/new.cat"] == nil || volume.paths["/alias.cat"] == nil {
		t.Fatalf("missing alias, paths = %v", volume.paths)
	}
	if volume.paths["/new.cat"].id != volume.paths["/alias.cat"].id {
		t.Fatal("alias does not share the generated MFT record")
	}
	if volume.paths["/old.cat"].id == volume.paths["/new.cat"].id {
		t.Fatal("replacing one link retargeted the surviving old sibling")
	}
	value, err := RecordBuiltin(nil, nil, starlark.Tuple{image, starlark.MakeUint64(volume.paths["/new.cat"].id)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	attrs, err := value.(starlark.HasAttrs).Attr("attributes")
	if err != nil {
		t.Fatal(err)
	}
	counts := map[uint64]int{}
	for v := range attrs.(*starlark.List).Elements() {
		attr := v.(starlark.HasAttrs)
		kind, _ := attr.Attr("type")
		typ, _ := kind.(starlark.Int).Uint64()
		if typ != 0x10 && typ != 0x30 {
			continue
		}
		data, _ := attr.Attr("value")
		bytes := []byte(data.(starlark.Bytes))
		offset := 0
		if typ == 0x30 {
			offset = 8
		}
		if len(bytes) < offset+32 {
			t.Fatal("short timestamp metadata")
		}
		for i, want := range []uint64{created, written, written, accessed} {
			if got := binary.LittleEndian.Uint64(bytes[offset+8*i:]); got != want {
				t.Fatalf("attribute %x timestamp %d = %d, want %d", typ, i, got, want)
			}
		}
		flagOffset := 32
		if typ == 0x30 {
			flagOffset = 56
		}
		if len(bytes) < flagOffset+4 || binary.LittleEndian.Uint32(bytes[flagOffset:])&0xff != 7 {
			t.Fatalf("attribute %x did not share normalized read-only/hidden/system flags: %x", typ, bytes)
		}
		counts[typ]++
	}
	if counts[0x10] != 1 || counts[0x30] != 2 {
		t.Fatalf("metadata forms = %v", counts)
	}
}
