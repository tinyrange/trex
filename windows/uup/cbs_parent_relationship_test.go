package uup

import (
	"reflect"
	"testing"
)

func TestCBSParentRelationshipsDifferFromUpdateScope(t *testing.T) {
	a := parentVersionIdentity("10.0.26100.1742")
	older := a
	older.Version = "10.0.26100.1"
	other := older
	other.Name = "Nested-Only-Package"
	wrong := older
	wrong.ProcessorArchitecture = "x86"
	index, err := NewCBSParentStateIndex([]CBSParentCandidate{
		{Identity: a, IntendedState: 0}, {Identity: older, IntendedState: 0x40, Baseline: true},
		{Identity: other, IntendedState: 0x70}, {Identity: wrong, IntendedState: 0x70},
	})
	if err != nil {
		t.Fatal(err)
	}
	m := parentStateManifest(t, "<parent disposition=\"absent\">"+scopeRef(a.Name, a.Version)+"<parent>"+scopeRef(other.Name, other.Version)+"</parent></parent>")
	descriptors := []CBSParentVersionComparison{{"EQ", "EQ", "EQ", true}, {"EQ", "EQ", "EQ", false}}
	got, err := index.ParentRelationships(m, descriptors)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, id := range got {
		seen[id.ExactKey()] = true
	}
	want := map[string]bool{a.ExactKey(): true, older.ExactKey(): true, other.ExactKey(): true}
	if !reflect.DeepEqual(seen, want) || len(got) != 3 {
		t.Fatalf("relationships=%v", got)
	}
	scope, err := index.ParentUpdateScope(m, descriptors)
	if err != nil || len(scope) != 1 || scope[0].ExactKey() != a.ExactKey() {
		t.Fatalf("scope=%v err=%v", scope, err)
	}
	// State and Baseline do not relax revision matching in the relationship path.
	descriptors[0] = CBSParentVersionComparison{"EQ", "EQ", "GE", false}
	got, err = index.ParentRelationships(m, descriptors)
	if err != nil || len(got) != 2 {
		t.Fatalf("range relationships=%v err=%v", got, err)
	}
	for _, id := range got {
		if id.ExactKey() == older.ExactKey() {
			t.Fatal("Baseline relaxed relationship")
		}
	}
	if got, err := index.ParentRelationships(m, descriptors[:1]); err == nil || got != nil {
		t.Fatal("accepted missing descriptor")
	}
}
