package repo

import (
	"context"
	"errors"
	"github.com/tinyrange/trex/storage"
	"testing"
)

func TestIndexedRefsLegacyFormat(t *testing.T) {
	r, e := Create(storage.NewMemoryStore(4 << 20))
	must(t, e)
	w := r.Empty()
	must(t, w.WriteFile("f", []byte("legacy")))
	id, e := w.Revision(RevisionMetadata{Message: "legacy provenance"})
	must(t, e)
	must(t, r.Promote("main", "", id))
	must(t, r.EnableIndexedRefs())
	must(t, r.Drop("main", id))
	must(t, r.Promote("restored", "", id))
	artifact, e := r.SnapshotFile()
	must(t, e)
	data := make([]byte, artifact.Size())
	_, e = artifact.ReadAt(data, 0)
	must(t, e)
	must(t, r.Close())
	store := storage.NewMemoryStore(4 << 20)
	_, e = store.WriteAt(data, 0)
	must(t, e)
	r, e = OpenVerified(store)
	must(t, e)
	defer r.Close()
	if !r.indexedRefs || r.Refs()["restored"] != id {
		t.Fatal("legacy indexed catalog lost")
	}
	w, e = r.Checkout("restored")
	must(t, e)
	readEquals(t, w, "f", []byte("legacy"))
}
func TestTargetMatchingHasIndependentBudget(t *testing.T) {
	r, e := CreateOptimized(storage.NewMemoryStore(4 << 20))
	must(t, e)
	defer r.Close()
	before := r.Empty()
	after, e := before.Fork()
	must(t, e)
	must(t, after.WriteFile("f", []byte("new")))
	targets := []TargetSpec{{Name: "a", Patterns: []string{"absent"}}, {Name: "b", Patterns: []string{"f"}}}
	_, e = AffectedTargets(context.Background(), before, after, targets, DiffOptions{Prefix: ".", MaxChanges: 10, MaxVisited: 100, MaxMatches: 1})
	if !errors.Is(e, ErrQueryLimit) {
		t.Fatal(e)
	}
}
