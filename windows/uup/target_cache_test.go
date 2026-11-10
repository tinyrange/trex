package uup

import (
	"bytes"
	"fmt"
	"sync"
	"testing"
)

func TestRuntimeTargetCacheHandoffOwnershipAndEviction(t *testing.T) {
	stage := &CumulativeStage{}
	before := bytes.Repeat([]byte("immutable verified basis"), 10000)
	held := stage.retainTarget("before", before, maximumCanonicalRetainedTarget)
	stage.ReleaseReadCaches()
	if len(stage.canonicalCache) != 0 || stage.canonicalRetained != 0 {
		t.Fatal("decoded cache survived handoff")
	}
	stage.packedTargets = newPackedTargetCache(2048)
	for i := 0; i < 12; i++ {
		key := fmt.Sprintf("entry%d", i)
		value := bytes.Repeat([]byte{byte(i)}, 128<<10)
		stage.retainTarget(key, value, maximumCanonicalRetainedTarget)
		clear(value) // Packed retention must own its bytes, not the input.
		got, err := stage.cachedTarget(key)
		if err != nil || len(got) != 128<<10 || !bytes.Equal(got, bytes.Repeat([]byte{byte(i)}, len(got))) {
			t.Fatalf("entry%d: %v", i, err)
		}
		if stage.packedTargets.used > stage.packedTargets.limit {
			t.Fatal("encoded budget exceeded")
		}
	}
	if got, err := stage.cachedTarget("entry0"); got != nil || err != nil {
		t.Fatal("oldest entry was not evicted")
	}
	if !bytes.Equal(held, before) {
		t.Fatal("handoff changed returned construction reader")
	}
	if len(stage.canonicalCache) != 0 || stage.canonicalRetained != 0 {
		t.Fatal("runtime repopulated decoded cache")
	}
	stage.releaseAssemblyFile("entry11")
	if got, err := stage.cachedTarget("entry11"); got != nil || err != nil {
		t.Fatal("explicit release retained compressed target")
	}
}

func TestRuntimeTargetCacheConcurrentReleaseAndStageIsolation(t *testing.T) {
	stages := []*CumulativeStage{{}, {}}
	for _, s := range stages {
		s.ReleaseReadCaches()
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s := stages[i%2]
			want := bytes.Repeat([]byte{byte(i%2 + 1)}, 64<<10)
			for pass := 0; pass < 30; pass++ {
				s.retainTarget("same-key", want, maximumCanonicalRetainedTarget)
				got, err := s.cachedTarget("same-key")
				if err != nil || (got != nil && !bytes.Equal(got, want)) {
					t.Errorf("stage%d content changed: %v", i%2, err)
					return
				}
				if pass%7 == 0 {
					s.ReleaseReadCaches()
				}
			}
		}()
	}
	wg.Wait()
	for _, s := range stages {
		s.ReleaseReadCaches()
		if s.packedTargets != nil {
			t.Fatal("compressed cache survived release")
		}
	}
}
