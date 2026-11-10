package uup

import (
	"crypto/sha256"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"testing"
)

func TestContentIndexPreservesPayloadPrecedenceAndNamedAlias(t *testing.T) {
	data := []byte("data")
	target := ContentDescriptor{Name: "first", Length: 4, SHA256: sha256.Sum256(data)}
	alias := target
	alias.Name = "alias"
	good := DeltaPayload{Literal: true, Target: target, RecordType: "RAW", Record: target}
	bad := good
	bad.Target = alias
	bad.Record.SHA256 = [32]byte{}
	stage := &CumulativeStage{PSF: &starfile.Bytes{Data: data}, Graph: &CumulativeGraph{Payloads: []DeltaPayload{good, bad}, Carries: []CarryPayload{{Target: alias, Source: alias}}}, canonicalCache: make(map[string][]byte), expressByTarget: map[string]*DeltaPayload{}}
	called := false
	stage.assemblyResolver = func(ContentDescriptor) (storage.Reader, error) {
		called = true
		return &starfile.Bytes{Data: data}, nil
	}
	query := target
	query.Name = "unmatched"
	f, ok, err := stage.openTargetDescriptor(query)
	if err != nil || !ok || f.Size() != 4 {
		t.Fatalf("first payload %v %v", ok, err)
	}
	query.Name = "ALIAS"
	if _, ok, err := stage.openTargetDescriptor(query); ok || err == nil {
		t.Fatal("bad named payload was replaced by another alias or carry")
	}
	if called {
		t.Fatal("payload failure fell through to carried content")
	}
	query.Length++
	if _, ok, err := stage.openTargetDescriptor(query); ok || err != nil {
		t.Fatal("different length matched exact-content index")
	}
}
