package filesystem

import (
	"io"
	"reflect"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

type cloneLazyReader struct{ reads int }

func (r *cloneLazyReader) Size() int64 { return 1 << 30 }
func (r *cloneLazyReader) ReadAt(p []byte, off int64) (int, error) {
	r.reads++
	return 0, io.ErrUnexpectedEOF
}

func TestDirectoryCloneMetadataAndLazyIsolation(t *testing.T) {
	d := New()
	reader := &cloneLazyReader{}
	lazy := starfile.NewReader("lazy", reader)
	d.PutFile("/Windows/large", FileRecord{File: lazy, Size: lazy.Size()})
	d.SetMetadata("/Windows/large", Metadata{
		SecurityDescriptor: []byte{1, 2, 3},
		ExtendedAttributes: []ExtendedAttribute{{Name: "Hint", Value: []byte{4, 5}}},
		NamedStreams:       map[string]starfile.File{"stream": lazy},
		ReparseTag:         0xa000000c, ReparseData: lazy,
		FileAttributes: 0x420, HasFileAttributes: true,
		CreationTime: 11, LastWriteTime: 22, LastAccessTime: 33, ShortName: "LARGE~1",
	})
	if err := d.SetAttributes("/Windows/large", Attributes{Hidden: true, System: true}); err != nil {
		t.Fatal(err)
	}
	if err := d.HardLink("/Windows/large", "/alias"); err != nil {
		t.Fatal(err)
	}
	m := d.metadata["/alias"]
	m.ShortName = "ALIAS~1"
	d.SetMetadata("/alias", m)
	d.PutFile("/data", FileRecord{Data: []byte("original"), Size: 8})
	d.Mkdir("/empty")
	d.SetMetadata("/empty", Metadata{SecurityDescriptor: []byte{7}, CreationTime: 44})
	// Warm derived caches: a clone must not borrow mutable cache storage.
	if _, err := d.listDirBuiltin(nil, nil, starlark.Tuple{starlark.String("/")}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := d.fatShortPath("/Windows/large"); err != nil {
		t.Fatal(err)
	}
	before := d.Snapshot()
	method, err := d.Attr("clone")
	if err != nil {
		t.Fatal(err)
	}
	value, err := starlark.Call(&starlark.Thread{Name: "clone"}, method, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	clone := value.(*Directory)
	if reader.reads != 0 || !reflect.DeepEqual(before, clone.Snapshot()) {
		t.Fatal("clone read lazy content or lost metadata")
	}
	if clone.files["/Windows/large"].File != lazy || clone.metadata["/alias"].ReparseData != lazy || clone.metadata["/alias"].NamedStreams["stream"] != lazy {
		t.Fatal("immutable readers were not preserved")
	}
	clone.files["/data"].Data[0] = 'X'
	clonedMeta := clone.metadata["/Windows/large"]
	clonedMeta.SecurityDescriptor[0] = 9
	clonedMeta.ExtendedAttributes[0].Value[0] = 9
	delete(clonedMeta.NamedStreams, "stream")
	if err := clone.SetTimes("/alias", 55, 66, 77); err != nil {
		t.Fatal(err)
	}
	if clone.metadata["/Windows/large"].LastWriteTime != 66 || clone.metadata["/Windows/large"].ShortName != "LARGE~1" || clone.metadata["/alias"].ShortName != "ALIAS~1" {
		t.Fatal("clone did not retain hardlinked metadata semantics")
	}
	if err := clone.RemoveEmptyDirectory("/empty"); err != nil {
		t.Fatal(err)
	}
	clone.PutFile("/new", FileRecord{Data: []byte("new"), Size: 3})
	if clone.files["/new"].WriteOrder <= before.Files["/data"].WriteOrder {
		t.Fatal("write order regressed")
	}
	if err := clone.HardLink("/new", "/new-alias"); err != nil {
		t.Fatal(err)
	}
	if clone.metadata["/new"].HardLink == clone.metadata["/alias"].HardLink {
		t.Fatal("cloned allocator reused a live identity")
	}
	if _, err := clone.removeBuiltin(nil, nil, starlark.Tuple{starlark.String("/alias")}, nil); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, d.Snapshot()) {
		t.Fatal("clone mutation leaked into source")
	}
	if d.hardLinkRefs[d.metadata["/alias"].HardLink] != 2 {
		t.Fatal("clone changed source reference counts")
	}
	if reader.reads != 0 {
		t.Fatal("clone mutations read lazy payload")
	}
	// Reverse isolation also matters when abandoning a failed transaction.
	sourceMeta := d.metadata["/empty"]
	sourceMeta.SecurityDescriptor[0] = 8
	d.PutFile("/source-only", FileRecord{})
	if _, ok := clone.files["/source-only"]; ok {
		t.Fatal("source write leaked into clone")
	}
	if _, err := starlark.Call(&starlark.Thread{Name: "clone"}, method, starlark.Tuple{starlark.None}, nil); err == nil {
		t.Fatal("clone accepted arguments")
	}
}
