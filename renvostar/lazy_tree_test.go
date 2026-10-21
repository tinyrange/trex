package renvostar

import (
	"context"
	"fmt"
	"github.com/tinyrange/trex/filesystem"
	"github.com/tinyrange/trex/scs/repo"
	scsstar "github.com/tinyrange/trex/scs/star"
	"github.com/tinyrange/trex/storage"
	"go.starlark.net/starlark"
	"testing"
)

type observedTree struct {
	filesystem.Tree
	opened   []string
	listings int
}

func (t *observedTree) OpenFile(p string) (storage.Reader, error) {
	t.opened = append(t.opened, p)
	return t.Tree.OpenFile(p)
}
func (t *observedTree) ReadDir(p string) ([]filesystem.TreeEntry, error) {
	t.listings++
	return nil, fmt.Errorf("unexpected eager directory listing: %s", p)
}

type observedSource struct {
	starlark.Value
	tree filesystem.Tree
}

func (s *observedSource) SnapshotTree() (filesystem.Tree, error) { return s.tree, nil }
func TestCBuildReadsOnlyRequestedTreeFiles(t *testing.T) {
	r, e := repo.CreateOptimized(storage.NewMemoryStore(2 << 20))
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	w := r.Empty()
	for p, body := range map[string]string{"main.c": "#include \"value.h\"\nint main(void) { return VALUE; }\n", "value.h": "#define VALUE 0\n", "unrelated.c": "invalid and must not be read"} {
		if e = w.WriteFile(p, []byte(body)); e != nil {
			t.Fatal(e)
		}
	}
	tree, e := w.SnapshotTree()
	if e != nil {
		t.Fatal(e)
	}
	tracked := &observedTree{Tree: tree}
	source := &observedSource{Value: scsstar.NewWorkspace(context.Background(), w), tree: tracked}
	result, e := starlark.Call(&starlark.Thread{}, Builtins()["cc"], nil, []starlark.Tuple{{starlark.String("source"), source}, {starlark.String("input"), starlark.String("main.c")}, {starlark.String("target"), starlark.String("windows/386")}, {starlark.String("arena_size"), starlark.MakeInt(1 << 20)}})
	if e != nil {
		t.Fatal(e)
	}
	module := result.(*compiledModule)
	if !module.result.Ok {
		t.Fatal(module.result.Diagnostic)
	}
	if len(tracked.opened) != 2 || tracked.listings != 0 {
		t.Fatal("build materialized unrelated inputs", tracked.opened, tracked.listings)
	}
	for _, p := range tracked.opened {
		if p != "main.c" && p != "value.h" {
			t.Fatal("unrequested payload", p)
		}
	}
	if len(w.Paths()) != 3 {
		t.Fatal("build mutated source")
	}
}
