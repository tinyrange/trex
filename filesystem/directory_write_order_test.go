package filesystem

import (
	"go.starlark.net/starlark"
	"testing"
)

func TestDirectoryWriteOrderTracksPathReplacementNotMetadata(t *testing.T) {
	d := New()
	order := func(path string) uint64 {
		t.Helper()
		value, err := d.getMetadataBuiltin(nil, nil, starlark.Tuple{starlark.String(path)}, nil)
		if err != nil {
			t.Fatal(err)
		}
		field, err := value.(starlark.HasAttrs).Attr("write_order")
		if err != nil {
			t.Fatal(err)
		}
		n, ok := field.(starlark.Int).Uint64()
		if !ok {
			t.Fatalf("invalid write order: %v", field)
		}
		return n
	}
	d.PutFile("/source", FileRecord{Data: []byte("abc"), Size: 3})
	first := order("/source")
	if first == 0 || order("/") != 0 {
		t.Fatal("file generation or directory sentinel missing")
	}
	if err := d.SetTimes("/source", 1, 2, 3); err != nil {
		t.Fatal(err)
	}
	if err := d.HardLink("/source", "/alias"); err != nil {
		t.Fatal(err)
	}
	d.PutFile("/other", FileRecord{Data: []byte("x"), Size: 1})
	if order("/source") != first {
		t.Fatal("metadata or another path invalidated source")
	}
	alias := order("/alias")
	d.PutFile("/source", FileRecord{Data: []byte("abc"), Size: 3})
	if order("/source") <= first || order("/alias") != alias {
		t.Fatal("replacement not path-local")
	}
	second := order("/source")
	if _, err := d.removeBuiltin(nil, nil, starlark.Tuple{starlark.String("/source")}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := d.getMetadataBuiltin(nil, nil, starlark.Tuple{starlark.String("/source")}, nil); err == nil {
		t.Fatal("removed path still exists")
	}
	d.PutFile("/source", FileRecord{Data: []byte("abc"), Size: 3})
	if order("/source") <= second {
		t.Fatal("remove/recreate reused binding generation")
	}
}
