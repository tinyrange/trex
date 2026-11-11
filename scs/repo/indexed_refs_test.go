package repo

import (
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/tinyrange/trex/storage"
)

func TestIndexedRefPromotionRecoveryAndScaling(t *testing.T) {
	for _, count := range []int{100, 10000} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			r, e := CreateOptimized(storage.NewMemoryStore(32 << 20))
			must(t, e)
			defer r.Close()
			a, e := r.Empty().Revision(RevisionMetadata{Message: "a"})
			must(t, e)
			b, e := r.Empty().Revision(RevisionMetadata{Message: "b"})
			must(t, e)
			must(t, r.EnableIndexedRefs())
			for i := 0; i < count; i++ {
				must(t, r.Promote(fmt.Sprintf("ref-%06d", i), "", a))
			}
			must(t, r.Checkpoint())
			before := r.OperationStats()
			must(t, r.Promote("ref-000000", a, b))
			after := r.OperationStats()
			if n := after.BytesAppended - before.BytesAppended; n > 16384 {
				t.Fatalf("one ref update appended %d bytes with %d refs", n, count)
			}
			t.Logf("%d refs: promotion appended %d records / %d bytes", count, after.RecordsAppended-before.RecordsAppended, after.BytesAppended-before.BytesAppended)
			if e = r.Promote("ref-000000", a, a); !errors.Is(e, ErrConflict) {
				t.Fatal(e)
			}
			file, e := r.SnapshotFile()
			must(t, e)
			data := make([]byte, file.Size())
			_, e = file.ReadAt(data, 0)
			must(t, e)
			for _, verified := range []bool{false, true} {
				store := storage.NewMemoryStore(32 << 20)
				_, e = store.WriteAt(data, 0)
				must(t, e)
				var reopened *Repository
				if verified {
					reopened, e = OpenVerified(store)
				} else {
					reopened, e = Open(store)
				}
				must(t, e)
				if len(reopened.Refs()) != count || reopened.Refs()["ref-000000"] != b || !reopened.indexedRefs {
					t.Fatal("lost indexed roots")
				}
				must(t, reopened.Drop("ref-000000", b))
				must(t, reopened.Close())
			}
		})
	}
}
func TestIndexedRefsConcurrentCASAndEmptyCatalog(t *testing.T) {
	r, e := CreateOptimized(storage.NewMemoryStore(8 << 20))
	must(t, e)
	defer r.Close()
	a, e := r.Empty().Snapshot()
	must(t, e)
	b, e := r.Empty().Revision(RevisionMetadata{Message: "b"})
	must(t, e)
	c, e := r.Empty().Revision(RevisionMetadata{Message: "c"})
	must(t, e)
	must(t, r.Promote("main", "", a))
	must(t, r.EnableIndexedRefs())
	must(t, r.Checkpoint())
	results := make(chan error, 2)
	var group sync.WaitGroup
	for _, id := range []ID{b, c} {
		group.Add(1)
		go func(id ID) { defer group.Done(); results <- r.Promote("main", a, id) }(id)
	}
	group.Wait()
	close(results)
	successes, conflicts := 0, 0
	for e := range results {
		if e == nil {
			successes++
		} else if errors.Is(e, ErrConflict) {
			conflicts++
		} else {
			t.Fatal(e)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatal(successes, conflicts)
	}
	must(t, r.Drop("main", r.Refs()["main"]))
	must(t, r.Checkpoint())
	file, e := r.SnapshotFile()
	must(t, e)
	data := make([]byte, file.Size())
	_, e = file.ReadAt(data, 0)
	must(t, e)
	store := storage.NewMemoryStore(8 << 20)
	_, e = store.WriteAt(data, 0)
	must(t, e)
	opened, e := Open(store)
	must(t, e)
	defer opened.Close()
	if len(opened.Refs()) != 0 || !opened.indexedRefs {
		t.Fatal("empty indexed catalog lost")
	}
}
