package repo

import (
	"context"
	"errors"
	"github.com/tinyrange/trex/storage"
	"testing"
)

type cancelReviewFile struct {
	repositoryFile
	cancel context.CancelFunc
	reads  int
}

func (f *cancelReviewFile) ReadAt(p []byte, off int64) (int, error) {
	f.reads++
	f.cancel()
	return f.repositoryFile.ReadAt(p, off)
}
func TestGlobContextCancelsDuringMetadataTraversal(t *testing.T) {
	r, e := CreateOptimized(storage.NewMemoryStore(4 << 20))
	must(t, e)
	defer r.Close()
	w := r.Empty()
	must(t, w.WriteFile("f", []byte("data")))
	id, e := w.Snapshot()
	must(t, e)
	must(t, r.Checkpoint())
	lazy, e := r.Fork(id)
	must(t, e)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	guard := &cancelReviewFile{repositoryFile: r.f, cancel: cancel}
	r.f = guard
	got, e := lazy.GlobContext(ctx, "**")
	if !errors.Is(e, context.Canceled) || got != nil || guard.reads == 0 {
		t.Fatalf("got=%v error=%v reads=%d", got, e, guard.reads)
	}
}
func TestRevisionRejectsMalformedUTF8WithoutWriting(t *testing.T) {
	r, e := CreateOptimized(storage.NewMemoryStore(4 << 20))
	must(t, e)
	defer r.Close()
	invalid := string([]byte{255})
	before := r.OperationStats()
	for _, meta := range []RevisionMetadata{{Author: invalid}, {Message: invalid}, {Task: invalid}} {
		if _, e = r.Empty().Revision(meta); e == nil {
			t.Fatal("malformed provenance was silently normalized")
		}
	}
	after := r.OperationStats()
	if after.RecordsAppended != before.RecordsAppended {
		t.Fatal("invalid metadata appended records")
	}
}
