package repo

import (
	"errors"
	"fmt"
	"math/rand"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
)

// Exercise page splits/collapses, deletion, ordering, and retention of historical versions
// against an independent map, not another tree implementation.
func TestPersistentIndexVersions(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	var root *childIndex
	model := map[string]*node{}
	type version struct {
		root  *childIndex
		model map[string]*node
	}
	versions := []version{}
	for i := 0; i < 3000; i++ {
		key := fmt.Sprintf("%03d", rng.Intn(300))
		if rng.Intn(3) == 0 {
			root = setChild(root, key, nil)
			delete(model, key)
		} else {
			value := &node{entry: Entry{Kind: "file", Size: int64(i)}}
			root = setChild(root, key, value)
			model[key] = value
		}
		if i%100 == 0 {
			copy := map[string]*node{}
			for k, v := range model {
				copy[k] = v
			}
			versions = append(versions, version{root, copy})
		}
	}
	versions = append(versions, version{root, model})
	for _, v := range versions {
		names := []string{}
		eachChild(v.root, func(k string, n *node) error {
			names = append(names, k)
			if v.model[k] != n || lookup(v.root, k) != n {
				t.Fatalf("version changed at %s", k)
			}
			return nil
		})
		if len(names) != len(v.model) || !sort.StringsAreSorted(names) {
			t.Fatal("index contents differ")
		}
		if count(v.root) != len(v.model) {
			t.Fatal("incorrect index count")
		}

	}
}

// Rebuild without sharing to independently verify canonical serialization after
// every mutation. This catches stale cached IDs, including directory chmod.
func rebuild(t *testing.T, w *Workspace) ID {
	t.Helper()
	fresh := w.r.Empty()
	fresh.s.source = w.s.source
	for _, p := range w.Paths() {
		e, err := w.Stat(p)
		must(t, err)
		switch e.Kind {
		case "dir":
			must(t, fresh.Mkdir(p))
		case "file":
			data, err := w.ReadFile(p)
			must(t, err)
			must(t, fresh.WriteFile(p, data))
		case "symlink":
			target, err := w.Readlink(p)
			must(t, err)
			must(t, fresh.Symlink(p, target))
		}
		if e.Kind != "symlink" {
			must(t, fresh.Chmod(p, e.Mode))
		}
	}
	id, err := fresh.Snapshot()
	must(t, err)
	return id
}

func TestSharedTreeMutationAndReopen(t *testing.T) {
	r, name := newRepo(t)
	w := r.Empty()
	for _, p := range []string{"a", "a/nested", "b", "untouched"} {
		must(t, w.Mkdir(p))
	}
	must(t, w.WriteFile("a/nested/f", []byte("original")))
	must(t, w.WriteFile("b/f", []byte("other")))
	must(t, w.WriteFile("untouched/f", []byte("same")))
	original, err := w.Snapshot()
	must(t, err)
	originalRoot := w.s.root
	readonly := w.Readonly()
	type saved struct {
		w  *Workspace
		id ID
	}
	savedVersions := []saved{{w, original}}
	operations := []func(*Workspace) error{
		func(w *Workspace) error { return w.WriteFile("a/nested/f", []byte("edited")) },
		func(w *Workspace) error { return w.Chmod("a/nested", 0700) },
		func(w *Workspace) error { return w.Chmod("a/nested/f", 0755) },
		func(w *Workspace) error { return w.Rename("a/nested", "b/moved") },
		func(w *Workspace) error { return w.Replace("b/moved/f", "edited", "replacement") },
		func(w *Workspace) error { return w.Symlink("b/link", "moved/f") },
		func(w *Workspace) error { return w.Symlink("b/link", "/outside") },
		func(w *Workspace) error { return w.Delete("b/f") },
		func(w *Workspace) error { return w.Mkdir("new") },
		func(w *Workspace) error { return w.Delete("a") },
		func(w *Workspace) error { return w.Rename("b", "new/renamed") },
	}
	for i, op := range operations {
		parent := savedVersions[len(savedVersions)-1].w
		f, err := parent.Fork()
		must(t, err)
		if f.s.root != parent.s.root {
			t.Fatal("fork copied tree")
		}
		must(t, op(f))
		if findNode(f.s.root, "untouched") != findNode(originalRoot, "untouched") {
			t.Fatal("unchanged subtree was copied")
		}
		id, err := f.Snapshot()
		must(t, err)
		if id != rebuild(t, f) {
			t.Fatalf("stale or noncanonical snapshot after mutation %d", i)
		}
		for _, old := range savedVersions {
			got, err := old.w.Snapshot()
			must(t, err)
			if got != old.id || rebuild(t, old.w) != old.id {
				t.Fatal("mutation leaked into an older fork")
			}
		}
		_, err = f.Publish(fmt.Sprintf("version%d", i))
		must(t, err)
		savedVersions = append(savedVersions, saved{f, id})
	}
	// Readonly remains live, unlike forks; caller-owned Stat slices cannot mutate it.
	must(t, w.WriteFile("a/nested/f", []byte("parent changed")))
	readEquals(t, readonly, "a/nested/f", []byte("parent changed"))
	e, err := w.Stat("a/nested/f")
	must(t, err)
	e.Blocks[0] = "bad"
	readEquals(t, w, "a/nested/f", []byte("parent changed"))
	must(t, r.Close())
	reopened, err := openTest(name)
	must(t, err)
	defer reopened.Close()
	for i, old := range savedVersions[1:] {
		got, err := reopened.Checkout(fmt.Sprintf("version%d", i))
		must(t, err)
		id, err := got.Snapshot()
		must(t, err)
		if id != old.id || rebuild(t, got) != id {
			t.Fatal("snapshot changed after reopening")
		}
	}
}

func TestSnapshotFastPathSafety(t *testing.T) {
	r, _ := newRepo(t)
	w := r.Empty()
	must(t, w.WriteFile("f", []byte("before")))
	id, err := w.Snapshot()
	must(t, err)
	root := w.s.root
	size, err := r.f.Stat()
	must(t, err)
	mustFail := w.WriteFrom("f", &brokenReader{})
	if mustFail == nil {
		t.Fatal("failed stream succeeded")
	}
	if w.s.root != root {
		t.Fatal("failed write dirtied the workspace")
	}
	same, err := w.Snapshot()
	must(t, err)
	if same != id {
		t.Fatal("failed write changed snapshot")
	}
	readEquals(t, w, "f", []byte("before"))
	// A clean snapshot/fork must neither append nor copy tree metadata.
	afterFailedWrite, err := r.f.Stat()
	must(t, err)
	if afterFailedWrite.Size() < size.Size() {
		t.Fatal("storage shrank")
	}
	for i := 0; i < 10; i++ {
		f, err := w.Fork()
		must(t, err)
		if f.s.root != root || f.s.snapshot != id {
			t.Fatal("fork did not share durable state")
		}
	}
	after, err := r.f.Stat()
	must(t, err)
	if after.Size() != afterFailedWrite.Size() {
		t.Fatal("clean fork appended records")
	}
	// Cached success must never bypass a poisoned or closed repository.
	r.poisoned = errors.New("injected sync failure")
	if _, err := w.Snapshot(); err == nil {
		t.Fatal("cached snapshot bypassed poison")
	}
	if _, err := w.Fork(); err == nil {
		t.Fatal("cached fork bypassed poison")
	}
	r.poisoned = nil
	must(t, r.Close())
	if _, err := w.Snapshot(); err == nil {
		t.Fatal("cached snapshot bypassed close")
	}
	if _, err := w.Fork(); err == nil {
		t.Fatal("cached fork bypassed close")
	}
}

func TestSharedForkConcurrentSnapshots(t *testing.T) {
	r, _ := newRepo(t)
	w := r.Empty()
	must(t, w.Mkdir("d"))
	must(t, w.WriteFile("d/f", []byte("base")))
	const workers = 8
	forks := make([]*Workspace, workers)
	for i := range forks {
		var err error
		forks[i], err = w.Fork()
		must(t, err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i, f := range forks {
		wg.Add(1)
		go func(i int, f *Workspace) {
			defer wg.Done()
			for j := 0; j < 30; j++ {
				if err := f.WriteFile("d/f", []byte(fmt.Sprintf("%d/%d", i, j))); err != nil {
					errs <- err
					return
				}
				if err := f.Chmod("d", uint32(0700+j%8)); err != nil {
					errs <- err
					return
				}
				if _, err := f.Snapshot(); err != nil {
					errs <- err
					return
				}
				if _, err := f.Fork(); err != nil {
					errs <- err
					return
				}
			}
		}(i, f)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		must(t, err)
	}
	readEquals(t, w, "d/f", []byte("base"))
	for i, f := range forks {
		readEquals(t, f, "d/f", []byte(fmt.Sprintf("%d/29", i)))
	}
}

func TestRenameDeepTreeFailureIsAtomic(t *testing.T) {
	r, _ := newRepo(t)
	w := r.Empty()
	must(t, w.Mkdir("src"))
	p := "src"
	for i := 0; i < 254; i++ {
		p += "/d"
		must(t, w.Mkdir(p))
	}
	must(t, w.WriteFile(p+"/f", nil))
	must(t, w.Mkdir("dest"))
	before := w.Paths()
	id, err := w.Snapshot()
	must(t, err)
	if err := w.Rename("src", "dest/src"); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("expected depth failure: %v", err)
	}
	if !reflect.DeepEqual(before, w.Paths()) {
		t.Fatal("failed rename changed paths")
	}
	after, err := w.Snapshot()
	must(t, err)
	if id != after {
		t.Fatal("failed rename changed snapshot")
	}
}
