package filesystem

import (
	"reflect"
	"testing"
)

func TestRemoveEmptyDirectoryPreservesChildrenAndSiblingPrefixes(t *testing.T) {
	d := New()
	d.Mkdir("/parent/remove/empty-child")
	d.PutFile("/parent/remove-later/file", FileRecord{Data: []byte("sibling"), Size: 7})
	d.SetMetadata("/parent/remove", Metadata{CreationTime: 123})
	before := d.Snapshot()
	for _, path := range []string{"/", "/parent/remove", "/parent/remove-later", "/parent/remove-later/file", "/missing"} {
		if err := d.RemoveEmptyDirectory(path); err == nil || !reflect.DeepEqual(before, d.Snapshot()) {
			t.Fatalf("nonempty/non-directory removal %q mutated the tree or succeeded: %v", path, err)
		}
	}
	if err := d.RemoveEmptyDirectory("/parent/remove/empty-child"); err != nil {
		t.Fatal(err)
	}
	if err := d.RemoveEmptyDirectory("/parent/remove"); err != nil {
		t.Fatal(err)
	}
	if _, ok := d.files["/parent/remove-later/file"]; !ok {
		t.Fatal("removed prefix sibling")
	}
	d.Mkdir("/parent/remove")
	if d.Snapshot().Metadata["/parent/remove"].CreationTime != 0 {
		t.Fatal("recreated directory retained deleted metadata")
	}
}
