package filesystem

import (
	"go.starlark.net/starlark"
	"testing"
)

func TestDirectoryListChildren(t *testing.T) {
	d := New()
	d.PutFile("/apps/one/child.dll", FileRecord{})
	d.PutFile("/apps/one/nested/other.dll", FileRecord{})
	d.PutFile("/apps/one/nested/more.dll", FileRecord{})
	d.PutFile("/apps/one-more/unrelated.dll", FileRecord{})
	d.Mkdir("/apps/one/empty")
	list := func(path, want string) {
		t.Helper()
		v, err := d.listDirBuiltin(nil, nil, starlark.Tuple{starlark.String(path)}, nil)
		if err != nil || v.String() != want {
			t.Fatalf("list_dir(%q) = %v, %v; want %s", path, v, err, want)
		}
	}
	list(`/apps/one/`, `["/apps/one/child.dll", "/apps/one/empty", "/apps/one/nested"]`)
	list(`/missing`, `[]`)
	list(`/apps/one/child.dll`, `[]`)
	list(`/`, `["/apps"]`)
	d.PutFile("/apps/one/added", FileRecord{})
	_, err := d.removeBuiltin(nil, nil, starlark.Tuple{starlark.String("/apps/one/child.dll")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	list(`/apps/one`, `["/apps/one/added", "/apps/one/empty", "/apps/one/nested"]`)
}
