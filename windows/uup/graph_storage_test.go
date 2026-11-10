package uup

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestCompactGraphPreservesContentAndInputDescriptors(t *testing.T) {
	graph := &CumulativeGraph{ContainerLength: 9827}
	var original []*ContentDescriptor
	for i := 0; i < 2000; i++ {
		name := fmt.Sprintf("component_%d/Σ%s.dll", i, strings.Repeat("long-name", 20))
		source := ContentDescriptor{Name: name, Length: int64(i), SHA256: sha256.Sum256([]byte(name)), nameHint: i%2 == 0}
		original = append(original, &source)
		graph.Sources = append(graph.Sources, source)
		graph.Carries = append(graph.Carries, CarryPayload{Target: source, Source: source})
		graph.Payloads = append(graph.Payloads, DeltaPayload{Target: source, Record: source, Basis: &source, RecordBasis: &source, RecordTarget: &source, DirectDelta: i%2 == 0, Literal: i%3 == 0, RecordOffset: int64(i * 13), RecordType: "PA30"})
	}
	before, err := json.Marshal(graph)
	if err != nil {
		t.Fatal(err)
	}
	graph.compactStorage()
	after, err := json.Marshal(graph)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("graph identities or payload semantics changed")
	}
	for i, p := range graph.Payloads {
		if p.Basis.nameHint != original[i].nameHint || *p.Basis != *original[i] {
			t.Fatalf("descriptor %d changed", i)
		}
	}
	original[0].Name = "input mutation"
	if graph.Payloads[0].Basis.Name == "input mutation" {
		t.Fatal("retained mutable input descriptor")
	}
	empty := &CumulativeGraph{}
	empty.compactStorage()
	if empty.Sources != nil || empty.Carries != nil || empty.Payloads != nil {
		t.Fatal("nil shape changed")
	}
}
