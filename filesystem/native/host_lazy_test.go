package native

import (
	"go.starlark.net/starlark"
	"os"
	"path/filepath"
	"testing"
)

func TestLazyHostConfinesPathsAndListsOnDemand(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	os.WriteFile(filepath.Join(outside, "secret"), []byte("outside"), 0600)
	os.Symlink(outside, filepath.Join(root, "link"))
	value, err := newLazyHost(nil, root)
	if err != nil {
		t.Fatal(err)
	}
	host := value.(*lazyHost)
	defer host.Close()
	// Creating this after construction distinguishes lazy listing from a walk.
	os.WriteFile(filepath.Join(root, "added.txt"), []byte("inside"), 0600)
	dir, found, err := host.Get(starlark.String("/"))
	if err != nil || !found {
		t.Fatal(err)
	}
	entries, err := dir.(starlark.HasAttrs).Attr("files")
	if err != nil {
		t.Fatal(err)
	}
	if entries.String() != `["/added.txt"]` {
		t.Fatal(entries)
	}
	for _, name := range []string{"/../secret", "/link/secret"} {
		if v, ok, err := host.Get(starlark.String(name)); err == nil && ok {
			t.Fatalf("escaped root at %s: %v", name, v)
		}
	}
}
