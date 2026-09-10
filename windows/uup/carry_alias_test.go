package uup

import (
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/tinyrange/trex/storage"
)

func TestDescriptorCarryTriesDeclaredHashEquivalentAliases(t *testing.T) {
	data := []byte("same verified bytes")
	missing := ContentDescriptor{Name: `amd64_missing_token_1.0_none_hash\file`, Length: int64(len(data)), SHA256: sha256.Sum256(data)}
	available := missing
	available.Name = `wow64_present_token_1.0_none_hash\file`
	for _, corrupt := range []bool{false, true} {
		stored := data
		if corrupt {
			stored = []byte("same incorrect data")
		}
		base := &testAssemblyArchive{files: map[string][]byte{"/image3/Windows/WinSxS/" + strings.ReplaceAll(available.Name, `\`, "/"): stored}}
		stage := &CumulativeStage{Graph: &CumulativeGraph{Carries: []CarryPayload{
			{Target: missing, Source: missing},
			{Target: missing, Source: missing}, // Duplicate source is tried once.
			{Target: available, Source: available},
		}}}
		stage.assemblyResolver = func(d ContentDescriptor) (storage.Reader, error) {
			return resolveBaseAssemblyDescriptor(base, "/image3", d)
		}
		query := missing
		query.Name = "different target version"
		_, ok, err := stage.openTargetDescriptor(query)
		if corrupt {
			if err == nil || ok {
				t.Fatal("accepted corrupt alias")
			}
		} else if err != nil || !ok {
			t.Fatalf("available alias hidden: %v", err)
		}
		if len(base.opened) != 2 {
			t.Fatalf("opened %v, want two distinct sources", base.opened)
		}
		base.opened = nil
		_, _, _ = stage.openTargetDescriptor(available)
		if !strings.Contains(base.opened[0], "wow64_present") {
			t.Fatal("exact name not preferred")
		}
		base.opened = nil
		query.SHA256 = [32]byte{}
		if _, ok, err := stage.openTargetDescriptor(query); ok || err != nil || len(base.opened) != 0 {
			t.Fatal("searched aliases with different content identity")
		}
	}
}
