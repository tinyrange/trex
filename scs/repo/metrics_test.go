package repo

import (
	"bytes"
	"github.com/tinyrange/trex/storage"
	"testing"
)

func TestSmallReadReportsWholeBodyDecode(t *testing.T) {
	r, e := CreateOptimized(storage.NewMemoryStore(8 << 20))
	must(t, e)
	w := r.Empty()
	payload := bytes.Repeat([]byte("0123456789abcdef"), 65536)
	must(t, w.WriteFile("large", payload))
	_, e = w.Publish("main")
	must(t, e)
	must(t, r.Checkpoint())
	artifact, e := r.SnapshotFile()
	must(t, e)
	data := make([]byte, artifact.Size())
	_, e = artifact.ReadAt(data, 0)
	must(t, e)
	must(t, r.Close())
	store := storage.NewMemoryStore(8 << 20)
	_, e = store.WriteAt(data, 0)
	must(t, e)
	r, e = Open(store)
	must(t, e)
	defer r.Close()
	w, e = r.Checkout("main")
	must(t, e)
	file, e := w.OpenReader("large")
	must(t, e)
	before := r.OperationStats()
	buf := make([]byte, 1)
	_, e = file.ReadAt(buf, 0)
	must(t, e)
	after := r.OperationStats()
	if after.BodyDecodes-before.BodyDecodes != 1 || after.BodyDecodedBytes-before.BodyDecodedBytes != uint64(len(payload)) {
		t.Fatal(before, after)
	}
	second, e := w.OpenReader("large")
	must(t, e)
	_, e = second.ReadAt(buf, 2)
	must(t, e)
	if r.OperationStats().BodyCacheHits <= after.BodyCacheHits {
		t.Fatal("body cache reuse not reported")
	}
}
