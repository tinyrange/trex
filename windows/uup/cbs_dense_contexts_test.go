package uup

import (
	"fmt"
	"strings"
	"testing"
)

func TestCBSDensePackageSnapshotBoundaries(t *testing.T) {
	template := cbsIntentManifest(t, "Template", "neutral", `<update name="feature"/>`)
	inputs := make([]CBSPackageIntent, MaxCBSPackageContexts)
	for i := range inputs {
		m := *template
		m.Identity.Name = fmt.Sprintf("Package-%05d", i)
		inputs[i] = CBSPackageIntent{Manifest: &m, IntendedState: CBSStateInstalled}
	}
	old, err := NewCBSUpdateStateIndex(inputs)
	if err != nil {
		t.Fatal(err)
	}
	changes := []CBSUpdateIntentChange{}
	for _, i := range []int{0, 15, 16, 1023, 1024, 65535, 65536, MaxCBSPackageContexts - 1} {
		changes = append(changes, CBSUpdateIntentChange{inputs[i].Manifest.Identity, CBSStateStaged})
	}
	next, err := old.WithIntendedStates(changes)
	if err != nil {
		t.Fatal(err)
	}
	for i, input := range inputs {
		id := input.Manifest.Identity
		want := uint32(CBSStateInstalled)
		for _, change := range changes {
			if change.Identity.Name == id.Name {
				want = CBSStateStaged
			}
		}
		got, err := next.PackageIntendedState(id)
		if err != nil || got != want {
			t.Fatalf("slot %d: %x, %v", i, got, err)
		}
		prior, err := old.PackageIntendedState(id)
		if err != nil || prior != CBSStateInstalled {
			t.Fatalf("old snapshot altered at %d", i)
		}
		id.Name = strings.ToUpper(id.Name)
		got, err = next.PackageIntendedState(id)
		if err != nil || got != want {
			t.Fatalf("identity fallback at %d: %x, %v", i, got, err)
		}
	}
	final, err := next.WithPublishedUpdates(inputs[MaxCBSPackageContexts-1].Manifest.Identity, map[string]uint32{"feature": CBSStateAbsent})
	if err != nil {
		t.Fatal(err)
	}
	before, err := next.UpdateState(inputs[MaxCBSPackageContexts-1].Manifest.Identity, "feature")
	if err != nil || before.IntendedState != CBSStateStaged {
		t.Fatal("publication poisoned previous snapshot", before, err)
	}
	after, err := final.UpdateState(inputs[MaxCBSPackageContexts-1].Manifest.Identity, "feature")
	if err != nil || after.IntendedState != CBSStateAbsent {
		t.Fatal(after, err)
	}
	if _, err := NewCBSUpdateStateIndex(append(inputs, inputs[0])); err == nil {
		t.Fatal("accepted oversized slot universe")
	}
}
