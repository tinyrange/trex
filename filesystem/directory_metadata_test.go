package filesystem

import (
	"reflect"
	"testing"

	"go.starlark.net/starlark"
)

func TestDirectoryTimesFollowFileIdentityNotRecreatedPath(t *testing.T) {
	d := New()
	d.PutFile("/source", FileRecord{Data: []byte("old"), Size: 3})
	d.SetMetadata("/source", Metadata{CreationTime: 1, LastWriteTime: 2, LastAccessTime: 3, ShortName: "SOURCE~1"})
	if err := d.HardLink("/source", "/alias"); err != nil {
		t.Fatal(err)
	}
	alias := d.Snapshot().Metadata["/alias"]
	alias.ShortName = "ALIAS~1"
	d.SetMetadata("/alias", alias)
	if err := d.SetTimes("/alias", 0x1122334455667788, 0x2233445566778899, 0x33445566778899aa); err != nil {
		t.Fatal(err)
	}
	first := d.Snapshot()
	if first.Metadata["/source"].LastWriteTime != 0x2233445566778899 || first.Metadata["/alias"].CreationTime != 0x1122334455667788 {
		t.Fatal("timestamps did not follow the hardlinked object")
	}
	if first.Metadata["/source"].ShortName != "SOURCE~1" || first.Metadata["/alias"].ShortName != "ALIAS~1" {
		t.Fatal("link-local metadata changed")
	}
	if _, err := d.removeBuiltin(nil, nil, starlark.Tuple{starlark.String("/source")}, nil); err != nil {
		t.Fatal(err)
	}
	d.PutFile("/source", FileRecord{Data: []byte("new"), Size: 3})
	if err := d.SetTimes("/source", 4, 5, 6); err != nil {
		t.Fatal(err)
	}
	if d.Snapshot().Metadata["/alias"].LastWriteTime != 0x2233445566778899 {
		t.Fatal("recreated path retargeted surviving alias metadata")
	}
	before := d.Snapshot()
	_, err := d.setTimesBuiltin(nil, nil, starlark.Tuple{starlark.String("/source"), starlark.MakeInt(-1), starlark.MakeInt(8), starlark.MakeInt(9)}, nil)
	if err == nil || !reflect.DeepEqual(before, d.Snapshot()) {
		t.Fatal("invalid unsigned timestamp was accepted or mutated the tree")
	}
	if err := d.SetTimes("/missing", 1, 2, 3); err == nil || !reflect.DeepEqual(before, d.Snapshot()) {
		t.Fatal("missing path was created by timestamp assignment")
	}
	value, err := d.getMetadataBuiltin(nil, nil, starlark.Tuple{starlark.String("/source")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := value.(starlark.HasAttrs).Attr("last_write_time")
	if err != nil || got != starlark.MakeUint64(5) {
		t.Fatalf("construction metadata = %v, %v", got, err)
	}
}
