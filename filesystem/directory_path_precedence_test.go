package filesystem

import (
	"go.starlark.net/starlark"
	"testing"
)

func TestPathNamesImpliedParentIsNotAFileCollision(t *testing.T) {
	d := New()
	d.PutFile("/A/child", FileRecord{})
	d.PutFile("/a", FileRecord{})
	names, err := d.buildPathNames(true, true)
	if err != nil {
		t.Fatal(err)
	}
	value, found, err := names.Get(starlark.String("/a"))
	if err != nil || !found || value != starlark.String("/a") {
		t.Fatalf("parent precedence: %v %v", value, err)
	}
	d.PutFile("/A", FileRecord{})
	if _, err := d.buildPathNames(true, true); err == nil {
		t.Fatal("actual file collision accepted")
	}
}
