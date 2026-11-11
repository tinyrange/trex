package repo

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"testing"

	"github.com/tinyrange/trex/storage"
)

func TestNativeRevisionGraphAndHistory(t *testing.T) {
	r, e := CreateOptimized(storage.NewMemoryStore(16 << 20))
	must(t, e)
	defer r.Close()
	w := r.Empty()
	must(t, w.WriteFile("file", []byte("first")))
	root, e := w.Revision(RevisionMetadata{Author: "agent", Message: "root", Task: "task"})
	must(t, e)
	plain, e := w.Snapshot()
	must(t, e)
	if plain == root {
		t.Fatal("provenance collapsed")
	}
	makeRev := func(message string, parents ...ID) ID {
		id, e := w.Revision(RevisionMetadata{Parents: parents, Message: message})
		must(t, e)
		return id
	}
	left := makeRev("left", root)
	right := makeRev("right", root)
	a := makeRev("merge-a", left, right)
	b := makeRev("merge-b", right, left)
	bases, e := r.MergeBases(context.Background(), a, b, GraphLimits{})
	must(t, e)
	want := []ID{left, right}
	sort.Slice(want, func(i, j int) bool { return want[i] < want[j] })
	if !reflect.DeepEqual(bases, want) {
		t.Fatal(bases, want)
	}
	yes, e := r.IsAncestor(context.Background(), root, a, GraphLimits{})
	must(t, e)
	if !yes {
		t.Fatal("lost root ancestry")
	}
	yes, e = r.IsAncestor(context.Background(), a, b, GraphLimits{})
	must(t, e)
	if yes {
		t.Fatal("siblings became ancestors")
	}
	if _, e = r.MergeBases(context.Background(), a, b, GraphLimits{MaxVisited: 1}); !errors.Is(e, ErrQueryLimit) {
		t.Fatal(e)
	}
	stats := r.OperationStats()
	_, e = r.MergeBases(context.Background(), a, b, GraphLimits{})
	must(t, e)
	if r.OperationStats().DerivedHits <= stats.DerivedHits {
		t.Fatal("derived index not reused")
	}
	r.ClearDerivedIndexes()
	rebuilt, e := r.MergeBases(context.Background(), a, b, GraphLimits{})
	must(t, e)
	if !reflect.DeepEqual(rebuilt, bases) {
		t.Fatal("cache rebuild changed answer")
	}
	rev, e := r.Revision(root)
	must(t, e)
	if rev.Author != "agent" || rev.Task != "task" || rev.Message != "root" {
		t.Fatal(rev)
	}
	if _, e = w.Revision(RevisionMetadata{Parents: []ID{root, root}}); e == nil {
		t.Fatal("duplicate parent accepted")
	}
	if _, e = w.Readonly().Revision(RevisionMetadata{}); !errors.Is(e, ErrReadOnly) {
		t.Fatal(e)
	}
	must(t, w.WriteFile("other", []byte("unrelated")))
	unrelated := makeRev("unrelated", a)
	must(t, w.WriteFile("file", []byte("second")))
	changed := makeRev("changed", unrelated)
	page, e := r.PathHistory(context.Background(), changed, "file", QueryLimits{Limit: 1})
	must(t, e)
	if len(page.Revisions) != 1 || page.Revisions[0].ID != changed || page.Next != unrelated {
		t.Fatal(page)
	}
	page, e = r.PathHistory(context.Background(), page.Next, "file", QueryLimits{Limit: 10})
	must(t, e)
	if len(page.Revisions) != 1 || page.Revisions[0].ID != root || page.Next != "" {
		t.Fatal(page)
	}
	must(t, r.EnableIndexedRefs())
	must(t, r.Promote("main", "", changed))
	must(t, r.Checkpoint())
	file, e := r.SnapshotFile()
	must(t, e)
	store := storage.NewMemoryStore(16 << 20)
	bytes := make([]byte, file.Size())
	_, e = file.ReadAt(bytes, 0)
	must(t, e)
	_, e = store.WriteAt(bytes, 0)
	must(t, e)
	reopened, e := OpenVerified(store)
	must(t, e)
	defer reopened.Close()
	saved, e := reopened.Revision(changed)
	must(t, e)
	if len(saved.Parents) != 1 || saved.Parents[0] != unrelated {
		t.Fatal(saved)
	}
	bases, e = reopened.MergeBases(context.Background(), a, b, GraphLimits{})
	must(t, e)
	if !reflect.DeepEqual(bases, want) {
		t.Fatal(bases)
	}
}
func TestRevisionQueriesCancelAndRejectMissing(t *testing.T) {
	r, e := CreateOptimized(storage.NewMemoryStore(4 << 20))
	must(t, e)
	defer r.Close()
	id, e := r.Empty().Revision(RevisionMetadata{})
	must(t, e)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = r.IsAncestor(ctx, id, id, GraphLimits{}); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if _, e = r.Revision(ID("bad")); e == nil {
		t.Fatal("invalid ID accepted")
	}
	if _, e = r.Empty().Revision(RevisionMetadata{Parents: []ID{ID("bad")}}); e == nil {
		t.Fatal("missing parent accepted")
	}
}
