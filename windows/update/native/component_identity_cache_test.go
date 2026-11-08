package native

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/tinyrange/trex/storage"
	bytecache "github.com/tinyrange/trex/storage/cache"
	starfile "github.com/tinyrange/trex/storage/star"
	"github.com/tinyrange/trex/windows/uup"
	"go.starlark.net/starlark"
)

func TestComponentCacheExactContentAliases(t *testing.T) {
	data := []byte("verified")
	hash := sha256.Sum256(data)
	other := sha256.Sum256([]byte("different"))
	descriptors := []uup.ContentDescriptor{
		{Name: "first", Length: 8, SHA256: hash},
		{Name: "alias", Length: 8, SHA256: hash},
		{Name: "different-length", Length: 9, SHA256: hash},
		{Name: "different-hash", Length: 8, SHA256: other},
	}
	stage := &uup.CumulativeStage{Graph: &uup.CumulativeGraph{}}
	plan := uup.StageEffectPlan{}
	for _, d := range descriptors {
		stage.Graph.Payloads = append(stage.Graph.Payloads, uup.DeltaPayload{Target: d})
		plan.Files = append(plan.Files, uup.StageFileEffect{SourceMode: "payload", SourceName: d.Name, StorePath: "/store/" + d.Name})
	}
	// A predecessor with the same full identity shares content too, but never
	// acquires a proof merely from its declaration.
	plan.Files = append(plan.Files, uup.StageFileEffect{SourceMode: "predecessor", SourceName: "previous", SourceDescriptor: &descriptors[0], StorePath: "/store/previous"})
	plan.Files = append(plan.Files, uup.StageFileEffect{SourceMode: "payload", SourceName: "first", StorePath: "/store/legacy", ExpectedSHA1: &[20]byte{}})
	value, err := componentStagingRecord(stage, plan, nil)
	if err != nil {
		t.Fatal(err)
	}
	open, _ := value.(starlark.HasAttrs).Attr("open")
	readers := make([]*reopenedStageReader, len(plan.Files))
	for i := range readers {
		v, err := starlark.Call(&starlark.Thread{}, open, starlark.Tuple{starlark.MakeInt(i)}, []starlark.Tuple{{starlark.String("lazy"), starlark.True}})
		if err != nil {
			t.Fatal(err)
		}
		readers[i] = v.(*starfile.ReaderValue).StorageReader().(*reopenedStageReader)
		if _, ok := readers[i].VerifiedSHA256(); ok {
			t.Fatal("declaration became verification")
		}
	}
	if readers[5].key == readers[0].key {
		t.Fatal("legacy check shared another manifest's cache key")
	}
	a, b := readers[0], readers[1]
	if a.key != b.key || a.key != readers[4].key || a.key == readers[2].key || a.key == readers[3].key || readers[2].key == readers[3].key {
		t.Fatal("cache identity lost hash/length separation")
	}
	originalCache := a.compressed
	cache, err := newStageContentCache(8 + 128)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range readers {
		r.compressed = cache
	}
	calls := 0
	a.open = func() (storage.Reader, error) { calls++; return &starfile.Bytes{Data: data}, nil }
	b.open = func() (storage.Reader, error) { calls++; return &starfile.Bytes{Data: data}, nil }
	got := make([]byte, len(data))
	if _, err = a.ReadAt(got, 0); err != nil || !bytes.Equal(got, data) {
		t.Fatal("first read", err)
	}
	legacyFailure := errors.New("manifest legacy digest mismatch")
	readers[5].open = func() (storage.Reader, error) { return nil, legacyFailure }
	if _, err := readers[5].ReadAt(got, 0); !errors.Is(err, legacyFailure) {
		t.Fatal("cached alias bypassed legacy verification", err)
	}
	if _, ok := b.VerifiedSHA256(); ok {
		t.Fatal("unread alias published proof")
	}
	if _, err = b.ReadAt(got, 0); err != nil || !bytes.Equal(got, data) || calls != 1 {
		t.Fatal("alias failed to share verified bytes", calls, err)
	}
	if digest, ok := b.VerifiedSHA256(); !ok || digest != hash {
		t.Fatal("alias lost content proof")
	}
	// Evict, then force the alias's own source to return wrong bytes. The old
	// verified identity must not bypass validation on a new reconstruction.
	_, err = cache.get(&reopenedStageReader{key: bytecache.Key{Index: 100}, size: 8, open: func() (storage.Reader, error) { return &starfile.Bytes{Data: []byte("evicting")}, nil }})
	if err != nil {
		t.Fatal(err)
	}
	b.open = func() (storage.Reader, error) { return &starfile.Bytes{Data: []byte("tampered")}, nil }
	if _, err = b.ReadAt(got, 0); err == nil {
		t.Fatal("evicted alias bypassed source verification")
	}
	// No process/global pool: another plan's equal content starts unverified.
	separate, err := componentStagingRecord(stage, plan, nil)
	if err != nil {
		t.Fatal(err)
	}
	open2, _ := separate.(starlark.HasAttrs).Attr("open")
	v, err := starlark.Call(&starlark.Thread{}, open2, starlark.Tuple{starlark.MakeInt(0)}, []starlark.Tuple{{starlark.String("lazy"), starlark.True}})
	if err != nil {
		t.Fatal(err)
	}
	r := v.(*starfile.ReaderValue).StorageReader().(*reopenedStageReader)
	if r.compressed == originalCache {
		t.Fatal("cache leaked across plans")
	}
	if _, ok := r.VerifiedSHA256(); ok {
		t.Fatal("proof leaked across plans")
	}
}

func TestDeclaredStageContentRequiresExactDescriptor(t *testing.T) {
	normalize := func(s string) string { return s }
	sizes := map[string]int64{"file": 8}
	hashes := map[string][32]byte{}
	effect := uup.StageFileEffect{SourceMode: "payload", SourceName: "file"}
	if _, _, known := declaredStageContent(effect, sizes, hashes, normalize); known {
		t.Fatal("size-only identity")
	}
	hashes["file"] = sha256.Sum256([]byte("verified"))
	effect.SourceMode = "metadata"
	if _, _, known := declaredStageContent(effect, sizes, hashes, normalize); known {
		t.Fatal("metadata trusted as payload")
	}
	effect.SourceMode = "predecessor"
	if _, _, known := declaredStageContent(effect, sizes, hashes, normalize); known {
		t.Fatal("predecessor without descriptor")
	}
}
