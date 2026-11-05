package native

import (
	"crypto/sha256"
	"errors"
	"github.com/tinyrange/trex/storage"
	bytecache "github.com/tinyrange/trex/storage/cache"
	starfile "github.com/tinyrange/trex/storage/star"
	"github.com/tinyrange/trex/windows/uup"
	"go.starlark.net/starlark"
	"io"
	"sync"
	"testing"
)

func TestReopenedStageReaderBoundariesAndRevalidation(t *testing.T) {
	calls := 0
	data := []byte("verified")
	var failure error
	r := &reopenedStageReader{size: 8, open: func() (storage.Reader, error) {
		calls++
		if failure != nil {
			return nil, failure
		}
		return &starfile.Bytes{Data: data}, nil
	}}
	if r.Size() != 8 || calls != 0 {
		t.Fatal("size read content")
	}
	p := make([]byte, 4)
	if n, err := r.ReadAt(p, 6); n != 2 || err != io.EOF || string(p[:n]) != "ed" {
		t.Fatal(n, err, p)
	}
	if n, err := r.ReadAt(p, 8); n != 0 || err != io.EOF || calls != 1 {
		t.Fatal(n, err, calls)
	}
	if _, err := r.ReadAt(p, -1); err == nil || calls != 1 {
		t.Fatal("negative offset read source")
	}
	failure = errors.New("reconstructed payload failed integrity")
	if _, err := r.ReadAt(p, 0); !errors.Is(err, failure) {
		t.Fatal("suppressed revalidation error", err)
	}
	failure = nil
	data = []byte("changed length")
	if _, err := r.ReadAt(p, 0); err == nil {
		t.Fatal("accepted unstable size")
	}
	data = []byte("verified")
	if n, err := r.ReadAt(p, 0); n != 4 || err != nil || string(p) != "veri" {
		t.Fatal(n, err, p)
	}
}

func TestStageReadersShareBoundedCacheAndReloadAfterEviction(t *testing.T) {
	cache := bytecache.New(8)
	calls := [2]int{}
	var failure error
	makeReader := func(i int) *reopenedStageReader {
		return &reopenedStageReader{size: 8, cache: cache, key: bytecache.Key{Index: i}, open: func() (storage.Reader, error) {
			calls[i]++
			if failure != nil {
				return nil, failure
			}
			return &starfile.Bytes{Data: []byte("verified")}, nil
		}}
	}
	a, b := makeReader(0), makeReader(1)
	p := make([]byte, 2)
	for i := 0; i < 4; i++ {
		if _, err := a.ReadAt(p, int64(i)); err != nil {
			t.Fatal(err)
		}
	}
	if calls[0] != 1 {
		t.Fatal("reopened on each adjacent read", calls)
	}
	if _, err := b.ReadAt(p, 0); err != nil {
		t.Fatal(err)
	}
	if cache.Stats().Bytes > 8 {
		t.Fatal("unbounded payload cache")
	}
	failure = errors.New("integrity failure after eviction")
	if _, err := a.ReadAt(p, 0); !errors.Is(err, failure) {
		t.Fatal("lost reconstruction failure", err)
	}
	if calls[0] != 2 {
		t.Fatal("eviction did not release first target", calls)
	}
}

func TestLazyStageReferenceDefersReconstructionButNotReadErrors(t *testing.T) {
	stage := &uup.CumulativeStage{Graph: &uup.CumulativeGraph{Payloads: []uup.DeltaPayload{{Target: uup.ContentDescriptor{Name: "payload", Length: 8}}}}}
	record, err := componentStagingRecord(stage, uup.StageEffectPlan{Files: []uup.StageFileEffect{{SourceMode: "payload", SourceName: "payload", StorePath: "/store/file"}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	open, _ := record.(starlark.HasAttrs).Attr("open")
	v, err := starlark.Call(&starlark.Thread{Name: "lazy staging"}, open, starlark.Tuple{starlark.MakeInt(0)}, []starlark.Tuple{{starlark.String("lazy"), starlark.True}})
	if err != nil {
		t.Fatal("lazy construction decoded content", err)
	}
	file := v.(storage.Reader)
	if file.Size() != 8 {
		t.Fatal(file.Size())
	}
	if _, err := file.ReadAt(make([]byte, 1), 0); err == nil {
		t.Fatal("missing content accepted on read")
	}
}

func TestStageVerifiedDigestRequiresFullValidationAndRechecksReopenedBytes(t *testing.T) {
	data := []byte("verified")
	expected := sha256.Sum256(data)
	r := &reopenedStageReader{size: 8, expectedSHA256: &expected, cache: bytecache.New(0), open: func() (storage.Reader, error) { return &starfile.Bytes{Data: data}, nil }}
	if _, ok := r.VerifiedSHA256(); ok {
		t.Fatal("declared hash treated as verified")
	}
	data = []byte("tampered")
	if _, err := r.ReadAt(make([]byte, 1), 0); err == nil {
		t.Fatal("accepted unverified content")
	}
	if _, ok := r.VerifiedSHA256(); ok {
		t.Fatal("failed read published digest")
	}
	data = []byte("verified")
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := r.ReadAt(make([]byte, 1), 0); err != nil {
				t.Error(err)
			}
			if d, ok := r.VerifiedSHA256(); !ok || d != expected {
				t.Error("lost verified identity")
			}
		}()
	}
	wg.Wait()
	data = []byte("tampered")
	// Eviction may lose bytes, never the identity. Future reads still reject
	// corrupt backing content instead of exposing it under the old digest.
	if _, err := r.ReadAt(make([]byte, 1), 0); err == nil {
		t.Fatal("reopen bypassed integrity")
	}
	if d, ok := r.VerifiedSHA256(); !ok || d != expected {
		t.Fatal("immutable identity changed")
	}
}
