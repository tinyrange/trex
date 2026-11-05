package filesystem

import (
	"fmt"
	"go.starlark.net/starlark"
	"testing"
)

func TestHardlinkIndexReassignmentAndCloneIsolation(t *testing.T) {
	d := New()
	for _, name := range []string{"/a", "/b", "/c", "/unrelated"} {
		d.PutFile(name, FileRecord{})
	}
	d.SetMetadata("/a", Metadata{HardLink: 700})
	d.SetMetadata("/b", Metadata{HardLink: 700, ShortName: "B~1"})
	d.SetMetadata("/c", Metadata{HardLink: 701})
	if err := d.HardLink("/a", "/alias"); err != nil {
		t.Fatal(err)
	}
	clone := d.Clone()
	// Reassign the same path to a different imported object, then remove a
	// surviving alias. Neither operation may leave an index entry behind.
	if err := clone.HardLink("/c", "/b"); err != nil {
		t.Fatal(err)
	}
	if _, err := clone.removeBuiltin(nil, nil, starlark.Tuple{starlark.String("/alias")}, nil); err != nil {
		t.Fatal(err)
	}
	if err := clone.SetTimes("/a", 1, 2, 3); err != nil {
		t.Fatal(err)
	}
	if clone.metadata["/b"].LastWriteTime != 0 || clone.metadata["/c"].LastWriteTime != 0 {
		t.Fatal("stale membership changed another object")
	}
	if _, exists := clone.metadata["/alias"]; exists {
		t.Fatal("deleted alias resurrected")
	}
	if err := clone.SetFileAttributes("/b", 32); err != nil {
		t.Fatal(err)
	}
	if err := clone.SetExtendedAttributes("/c", []ExtendedAttribute{{Name: "keep", Value: []byte("v")}}); err != nil {
		t.Fatal(err)
	}
	if clone.metadata["/c"].FileAttributes != 32 || len(clone.metadata["/b"].ExtendedAttributes) != 1 {
		t.Fatal("reassigned aliases did not share metadata")
	}
	if clone.metadata["/b"].ShortName != "B~1" {
		t.Fatal("lost entry-local short name")
	}
	if err := d.SetTimes("/alias", 4, 5, 6); err != nil {
		t.Fatal(err)
	}
	if d.metadata["/a"].LastWriteTime != 5 || d.metadata["/b"].LastWriteTime != 5 || clone.metadata["/a"].LastWriteTime != 2 {
		t.Fatal("clone shared identity index storage")
	}
}

func BenchmarkHardlinkMetadataLargeTree(b *testing.B) {
	d := New()
	for i := 0; i < 100000; i++ {
		name := fmt.Sprintf("/file/%d", i)
		d.PutFile(name, FileRecord{})
		d.SetMetadata(name, Metadata{HardLink: uint64(i + 100)})
	}
	if err := d.HardLink("/file/0", "/alias"); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := d.SetTimes("/alias", uint64(i), 2, 3); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPruneEmptyDirectoriesLargeTree(b *testing.B) {
	for n := 0; n < b.N; n++ {
		b.StopTimer()
		d := New()
		for i := 0; i < 100000; i++ {
			d.PutFile(fmt.Sprintf("/files/%d", i), FileRecord{})
		}
		for i := 0; i < 500; i++ {
			d.Mkdir(fmt.Sprintf("/prune/%d", i))
		}
		b.StartTimer()
		for i := 0; i < 500; i++ {
			if err := d.RemoveEmptyDirectory(fmt.Sprintf("/prune/%d", i)); err != nil {
				b.Fatal(err)
			}
		}
	}
}
