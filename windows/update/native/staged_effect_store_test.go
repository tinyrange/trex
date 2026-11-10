package native

import (
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"github.com/tinyrange/trex/windows/uup"
	"sync"
	"testing"
)

func TestStagedEffectStoreOwnsConstraintsAcrossSlabs(t *testing.T) {
	var store stagedEffectStore
	effects := make([]uup.StageFileEffect, 3000)
	var wg sync.WaitGroup
	for worker := range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := worker; i < len(effects); i += 4 {
				name := fmt.Sprintf("/component/日本語/%d/long-file-name.dll", i)
				hash := sha256.Sum256([]byte(name))
				legacy := sha1.Sum([]byte(name))
				descriptor := uup.ContentDescriptor{Name: name, Length: int64(i), SHA256: hash}
				effects[i] = store.own(uup.StageFileEffect{Architecture: "amd64", SourceName: name, StorePath: name, SourceDescriptor: &descriptor, ExpectedSHA256: &hash, ExpectedSHA1: &legacy})
				descriptor.Name = "changed"
				descriptor.Length = -1
				hash = [32]byte{}
				legacy = [20]byte{}
			}
		}()
	}
	wg.Wait()
	for i, effect := range effects {
		name := fmt.Sprintf("/component/日本語/%d/long-file-name.dll", i)
		if effect.SourceName != name || effect.StorePath != name || effect.SourceDescriptor.Name != name || effect.SourceDescriptor.Length != int64(i) || *effect.ExpectedSHA256 != sha256.Sum256([]byte(name)) || *effect.ExpectedSHA1 != sha1.Sum([]byte(name)) {
			t.Fatalf("identity %d changed", i)
		}
	}
}
