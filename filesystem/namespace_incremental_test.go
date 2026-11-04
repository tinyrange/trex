package filesystem

import (
	"go.starlark.net/starlark"
	"reflect"
	"testing"
)

func TestChildrenIndexSurvivesMixedNamespaceEdits(t *testing.T) {
	d := New()
	d.PutFile("/a/z", FileRecord{})
	d.ensureChildren()
	original, err := d.listDirBuiltin(nil, nil, starlark.Tuple{starlark.String("/a")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Exercise sorted insertion, missing parent creation, and coincident file
	// and directory names. Removing the file must retain the directory entry.
	d.PutFile("/a/b", FileRecord{})
	d.PutFile("/a/m/n", FileRecord{})
	d.PutFile("/a/m", FileRecord{})
	if _, err := d.removeBuiltin(nil, nil, starlark.Tuple{starlark.String("/a/m")}, nil); err != nil {
		t.Fatal(err)
	}
	if d.childrenRevision != d.revision {
		t.Fatal("index invalidated by local edits")
	}
	if got := d.children["/a"]; !reflect.DeepEqual(got, []string{"/a/b", "/a/m", "/a/z"}) {
		t.Fatal(got)
	}
	if original.String() != `["/a/z"]` {
		t.Fatal("caller list changed", original)
	}
	clone := d.Clone()
	clone.ensureChildren()
	if _, err := clone.removeBuiltin(nil, nil, starlark.Tuple{starlark.String("/a/m/n")}, nil); err != nil {
		t.Fatal(err)
	}
	if err := clone.RemoveEmptyDirectory("/a/m"); err != nil {
		t.Fatal(err)
	}
	if len(d.children["/a/m"]) != 1 {
		t.Fatal("clone mutated original index")
	}
	// A fresh rebuild is the independent oracle for every maintained parent.
	maintained := clone.children
	clone.children = nil
	clone.ensureChildren()
	for parent, names := range maintained {
		if !reflect.DeepEqual(names, clone.children[parent]) && len(names)+len(clone.children[parent]) != 0 {
			t.Fatalf("%s: %v != %v", parent, names, clone.children[parent])
		}
	}
}
