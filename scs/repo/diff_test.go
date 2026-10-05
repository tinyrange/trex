package repo

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"sync"
	"testing"
)

// exhaustiveDiff is a deliberately separate traversal oracle: enumerate every
// path and compare fully described entries, never use IDs to prune traversal.
func exhaustiveDiff(t *testing.T, a, b *Workspace) []Change {
	t.Helper()
	names := map[string]uint8{}
	for i, w := range []*Workspace{a, b} {
		paths, err := w.PathsWithError()
		must(t, err)
		for _, p := range paths {
			names[p] |= 1 << i
		}
	}
	var sorted []string
	for p := range names {
		sorted = append(sorted, p)
	}
	sort.Strings(sorted)
	changes := make([]Change, 0)
	for _, p := range sorted {
		c := Change{Path: p}
		if names[p]&1 != 0 {
			e, err := a.Stat(p)
			must(t, err)
			c.Before, err = describeEntry(context.Background(), a.r, e)
			must(t, err)
		}
		if names[p]&2 != 0 {
			e, err := b.Stat(p)
			must(t, err)
			c.After, err = describeEntry(context.Background(), b.r, e)
			must(t, err)
		}
		switch {
		case c.Before == nil:
			c.Status = "added"
		case c.After == nil:
			c.Status = "deleted"
		case *c.Before != *c.After:
			c.Status = "modified"
		default:
			continue
		}
		changes = append(changes, c)
	}
	return changes
}
func TestPrunedDiffMatchesExhaustiveTraversal(t *testing.T) {
	for _, mode := range []string{"v2", "v3", "paged"} {
		t.Run(mode, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "r.scs")
			createTestMode := createTestOptimized
			if mode == "v2" {
				createTestMode = createTest
			}
			r, err := createTestMode(file)
			must(t, err)
			before := r.Empty()
			for _, dir := range []string{"wide", "mode-only", "removed", "becomes-file", "empty"} {
				must(t, before.Mkdir(dir))
			}
			for i := 0; i < 90; i++ {
				must(t, before.WriteFile(fmt.Sprintf("wide/f%03d", i), []byte(fmt.Sprintf("data %d", i))))
			}
			must(t, before.WriteFile("mode-only/nested", []byte("same")))
			must(t, before.WriteFile("becomes-file/nested", []byte("removed")))
			must(t, before.WriteFile("becomes-dir", []byte("old")))
			must(t, before.WriteFile("removed/a", []byte("old")))
			must(t, before.Symlink("link", "wide/f000"))
			old, err := before.Publish("before")
			must(t, err)
			after, err := r.Fork(old)
			must(t, err)
			// Wide branch collapse, additions, mode-only directory/file changes,
			// timestamp-only changes, type replacements, and a moved subtree.
			for i := 0; i < 70; i++ {
				must(t, after.Delete(fmt.Sprintf("wide/f%03d", i)))
			}
			must(t, after.WriteFile("wide/new", []byte("added")))
			must(t, after.WriteFile("wide/f070", []byte("changed")))
			must(t, after.Chmod("wide/f071", 0755))
			must(t, after.SetTimes("wide/f072", Times{M: 12345}))
			must(t, after.Chmod("mode-only", 0700))
			must(t, after.Delete("removed/a"))
			must(t, after.Delete("removed"))
			must(t, after.Delete("becomes-file/nested"))
			must(t, after.Delete("becomes-file"))
			must(t, after.WriteFile("becomes-file", []byte("now regular")))
			must(t, after.Delete("becomes-dir"))
			must(t, after.Mkdir("becomes-dir"))
			must(t, after.WriteFile("becomes-dir/nested", []byte("new")))
			must(t, after.Delete("link"))
			must(t, after.Symlink("link", "elsewhere"))
			must(t, after.Rename("empty", "moved-empty"))
			compare := func(a, b *Workspace) {
				t.Helper()
				got, err := Diff(context.Background(), a, b)
				must(t, err)
				want := exhaustiveDiff(t, a, b)
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("pruned != exhaustive\ngot %#v\nwant %#v", got, want)
				}
			}
			compare(before, after)
			compare(after, before) // unpublished persistent roots
			_, err = after.Publish("after")
			must(t, err)
			if mode == "paged" {
				must(t, r.Checkpoint())
			}
			must(t, r.Close())
			r, err = openTest(file)
			must(t, err)
			defer r.Close()
			before, err = r.Checkout("before")
			must(t, err)
			after, err = r.Checkout("after")
			must(t, err)
			compare(before, after)
			compare(after, before)
			same, err := Diff(context.Background(), after, after.Readonly())
			must(t, err)
			if len(same) != 0 {
				t.Fatal(same)
			}
		})
	}
}

type reviewReadGuard struct {
	repositoryFile
	forbidden    map[int64]bool
	reads, bytes int
}

func (f *reviewReadGuard) ReadAt(p []byte, off int64) (int, error) {
	f.reads++
	f.bytes += len(p)
	if f.forbidden[off] {
		return 0, fmt.Errorf("read skipped subtree at %d", off)
	}
	return f.repositoryFile.ReadAt(p, off)
}
func TestPrunedDiffDoesNotReadUnchangedSubtree(t *testing.T) {
	file := filepath.Join(t.TempDir(), "r.scs")
	r, err := createTestOptimized(file)
	must(t, err)
	w := r.Empty()
	must(t, w.Mkdir("unchanged"))
	for i := 0; i < 1000; i++ {
		must(t, w.WriteFile(fmt.Sprintf("unchanged/file-%04d", i), []byte(fmt.Sprintf("payload-%d", i))))
	}
	must(t, w.WriteFile("edited", []byte("old")))
	old, err := w.Publish("before")
	must(t, err)
	subtree := findNode(w.s.root, "unchanged")
	loc, ok := r.lookupObject(key(subtree.id))
	if !ok {
		t.Fatal("missing subtree")
	}
	after, err := r.Fork(old)
	must(t, err)
	must(t, after.WriteFile("edited", []byte("new")))
	must(t, after.Chmod("unchanged", 0700)) // same tree ID, distinct parent mode
	_, err = after.Publish("after")
	must(t, err)
	must(t, r.Checkpoint())
	must(t, r.Close())
	r, err = openTest(file)
	must(t, err)
	defer r.Close()
	a, err := r.Checkout("before")
	must(t, err)
	b, err := r.Checkout("after")
	must(t, err)
	guard := &reviewReadGuard{repositoryFile: r.f, forbidden: map[int64]bool{loc.offset: true}}
	r.f = guard
	got, err := Diff(context.Background(), a, b)
	must(t, err)
	if len(got) != 2 || got[0].Path != "edited" || got[1].Path != "unchanged" || got[1].After.Mode != 0700 {
		t.Fatal(got)
	}
	t.Logf("one edit + directory chmod across 1000 untouched files: %d reads, %d requested bytes", guard.reads, guard.bytes)
	// Entirely identical lazy roots require no descriptor or body reads.
	guard.reads = 0
	guard.bytes = 0
	same, err := Diff(context.Background(), a, a.Readonly())
	must(t, err)
	if len(same) != 0 || guard.reads != 0 {
		t.Fatalf("same root reads=%d diff=%v", guard.reads, same)
	}
}
func TestPrunedDiffCorruptionIsNotAScrub(t *testing.T) {
	file := filepath.Join(t.TempDir(), "r.scs")
	r, err := createTestOptimized(file)
	must(t, err)
	a := r.Empty()
	must(t, a.WriteFile("unchanged", []byte("same")))
	must(t, a.WriteFile("edited", []byte("old")))
	old, err := a.Publish("before")
	must(t, err)
	loc, _ := r.lookupObject(key(findNode(a.s.root, "unchanged").id))
	b, err := r.Fork(old)
	must(t, err)
	must(t, b.WriteFile("edited", []byte("new")))
	_, err = b.Publish("after")
	must(t, err)
	changedLoc, _ := r.lookupObject(key(findNode(b.s.root, "edited").id))
	must(t, r.Checkpoint())
	must(t, r.Close())
	corrupt := func(off int64) {
		f, err := os.OpenFile(file, os.O_RDWR, 0)
		must(t, err)
		_, err = f.WriteAt([]byte{'!'}, off)
		must(t, err)
		must(t, f.Close())
	}
	corrupt(loc.offset)
	r, err = openTest(file)
	must(t, err)
	a, err = r.Checkout("before")
	must(t, err)
	b, err = r.Checkout("after")
	must(t, err)
	got, err := Diff(context.Background(), a, b)
	must(t, err)
	if len(got) != 1 || got[0].Path != "edited" {
		t.Fatal(got)
	}
	if err = r.Scrub(false); err == nil {
		t.Fatal("scrub missed skipped corruption")
	}
	// Scrub may poison/mark the repository; its Close status is not the assertion.
	_ = r.Close()
	corrupt(changedLoc.offset)
	r, err = openTest(file)
	must(t, err)
	defer r.Close()
	a, err = r.Checkout("before")
	must(t, err)
	b, err = r.Checkout("after")
	must(t, err)
	if _, err = Diff(context.Background(), a, b); err == nil {
		t.Fatal("diff hid accessed corruption")
	}
}
func TestDiffCapturesLiveRootsWithoutPublishing(t *testing.T) {
	r, _ := newRepo(t)
	a := r.Empty()
	must(t, a.WriteFile("f", []byte("original")))
	id, err := a.Publish("main")
	must(t, err)
	b, err := r.Fork(id)
	must(t, err)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			if err := b.WriteFile("f", []byte(fmt.Sprint(i))); err != nil {
				t.Error(err)
				return
			}
			if _, err := b.Snapshot(); err != nil {
				t.Error(err)
				return
			} // memoizes shared IDs
		}
	}()
	for i := 0; i < 50; i++ {
		got, err := Diff(context.Background(), a, b)
		must(t, err)
		if len(got) > 1 || len(got) == 1 && got[0].Path != "f" {
			t.Fatal(got)
		}
	}
	wg.Wait()
	if r.Refs()["main"] != id || len(r.Refs()) != 1 {
		t.Fatal("diff published")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Diff(ctx, a, b); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
