package native

import (
	"crypto/sha1"
	"crypto/sha256"
	"testing"

	"github.com/tinyrange/trex/windows/uup"
)

func TestDeferredEffectOwnsContentConstraints(t *testing.T) {
	digest := sha256.Sum256([]byte("admitted"))
	legacy := sha1.Sum([]byte("admitted"))
	descriptor := uup.ContentDescriptor{Name: "source", Length: 8, SHA256: digest}
	effect := uup.StageFileEffect{Kind: "component-file", SourceMode: "predecessor", SourceName: "source", SourceDescriptor: &descriptor, ExpectedSHA256: &digest, ExpectedSHA1: &legacy}
	var store stagedEffectStore
	owned := store.own(effect)
	// A caller can release or reuse its plan after creating a deferred reader.
	// Neither a descriptor mutation nor a shared digest pointer may change the
	// content constraints used later, including after cache eviction.
	descriptor.Name = "reused"
	descriptor.Length = 99
	descriptor.SHA256 = [32]byte{}
	digest = [32]byte{}
	legacy = [20]byte{}
	if owned.SourceDescriptor.Name != "source" || owned.SourceDescriptor.Length != 8 || owned.SourceDescriptor.SHA256 != sha256.Sum256([]byte("admitted")) || *owned.ExpectedSHA256 != owned.SourceDescriptor.SHA256 || *owned.ExpectedSHA1 != sha1.Sum([]byte("admitted")) {
		t.Fatal("deferred effect followed mutable plan constraints")
	}
}
