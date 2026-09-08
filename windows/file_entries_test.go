package windows

import (
	"go.starlark.net/starlark"
	"testing"
)

func TestCloneFileEntriesOwnershipAndOrder(t *testing.T) {
	entries := starlark.NewDict(2)
	payload := starlark.NewList([]starlark.Value{starlark.String("extension")})
	for _, path := range []string{"z", "a"} {
		entry := starlark.NewDict(3)
		_ = entry.SetKey(starlark.String("directory"), starlark.False)
		_ = entry.SetKey(starlark.String("size"), starlark.MakeInt(42))
		_ = entry.SetKey(starlark.String("extra"), payload)
		_ = entries.SetKey(starlark.String(path), entry)
	}
	entries.Freeze()
	value, err := cloneFileEntriesBuiltin(nil, nil, starlark.Tuple{entries}, nil)
	if err != nil {
		t.Fatal(err)
	}
	cloned := value.(*starlark.Dict)
	if equal, err := starlark.Equal(entries, cloned); err != nil || !equal {
		t.Fatalf("copy differs: %v", err)
	}
	if cloned.Keys()[0] != starlark.String("z") {
		t.Fatal("path order changed")
	}
	first, _, _ := cloned.Get(starlark.String("z"))
	entry := first.(*starlark.Dict)
	if entry.Keys()[0] != starlark.String("directory") {
		t.Fatal("field order changed")
	}
	shared, _, _ := entry.Get(starlark.String("extra"))
	if shared != payload {
		t.Fatal("payload was deep copied")
	}
	if err := entry.SetKey(starlark.String("size"), starlark.MakeInt(7)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := cloned.Delete(starlark.String("a")); err != nil {
		t.Fatal(err)
	}
	original, _, _ := entries.Get(starlark.String("z"))
	size, _, _ := original.(*starlark.Dict).Get(starlark.String("size"))
	if entries.Len() != 2 || size != starlark.MakeInt(42) {
		t.Fatal("copy mutated original")
	}
}
