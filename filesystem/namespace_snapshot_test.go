package filesystem

import (
	"go.starlark.net/starlark"
	"testing"
)

func TestNamespaceSnapshotLifetime(t *testing.T) {
	d := New()
	d.PutFile("/Windows/A", FileRecord{Data: []byte("a"), Size: 1})
	snapshot := func(empty bool) *starlark.Dict {
		t.Helper()
		v, err := d.pathNamesBuiltin(nil, nil, nil, []starlark.Tuple{
			{starlark.String("lower"), starlark.True},
			{starlark.String("include_empty"), starlark.Bool(empty)},
			{starlark.String("readonly"), starlark.True},
		})
		if err != nil {
			t.Fatal(err)
		}
		return v.(*starlark.Dict)
	}
	old := snapshot(false)
	if err := old.Clear(); err == nil {
		t.Fatal("snapshot is mutable")
	}
	revision := d.revision
	order := d.files["/Windows/A"].WriteOrder
	d.PutFile("/Windows/A", FileRecord{Data: []byte("b"), Size: 1})
	if d.revision != revision || snapshot(false) != old || d.files["/Windows/A"].WriteOrder == order {
		t.Fatal("content write must advance content order but preserve namespace snapshot")
	}
	list := d.fileList()
	if err := list.SetIndex(0, starlark.String("bad")); err != nil {
		t.Fatal(err)
	}
	if d.fileList().Index(0) != starlark.String("/Windows/A") {
		t.Fatal("mutable file list aliases cache")
	}
	d.Mkdir("/Empty")
	if _, found, _ := snapshot(false).Get(starlark.String("/empty")); found {
		t.Fatal("empty directory leaked into file namespace")
	}
	if _, found, _ := snapshot(true).Get(starlark.String("/empty")); !found {
		t.Fatal("missing empty directory")
	}
	if err := d.RemoveEmptyDirectory("/Empty"); err != nil {
		t.Fatal(err)
	}
	if _, found, _ := snapshot(true).Get(starlark.String("/empty")); found {
		t.Fatal("removed directory stayed cached")
	}
	d.PutFile("/windows/B", FileRecord{})
	if _, err := d.removeBuiltin(nil, nil, starlark.Tuple{starlark.String("/Windows/A")}, nil); err != nil {
		t.Fatal(err)
	}
	now := snapshot(false)
	parent, _, _ := now.Get(starlark.String("/windows"))
	if parent != starlark.String("/windows") {
		t.Fatal("parent spelling did not follow new first descendant")
	}
	if _, found, _ := old.Get(starlark.String("/windows/a")); !found {
		t.Fatal("old snapshot changed")
	}
	clone := d.Clone()
	clone.PutFile("/other", FileRecord{})
	if _, found, _ := snapshot(false).Get(starlark.String("/other")); found {
		t.Fatal("clone changed source namespace")
	}
}
