package uup

import (
	"fmt"
	"testing"
)

func cbsSnapshotInventory(count int) []CBSPackageIntent {
	inputs := make([]CBSPackageIntent, count)
	for i := range inputs {
		inputs[i] = CBSPackageIntent{Manifest: &AssemblyManifest{
			Identity: AssemblyIdentity{Name: fmt.Sprintf("Inventory-%05d", i), Version: "1.0.0.0", ProcessorArchitecture: "amd64", PublicKeyToken: "31bf3856ad364e35"},
			Package:  &AssemblyPackage{}, PackageUpdates: []AssemblyPackageUpdate{{Name: "feature"}},
		}, IntendedState: CBSStateInstalled}
	}
	return inputs
}

func TestCBSSnapshotRetainedInventoryIsolation(t *testing.T) {
	inputs := cbsSnapshotInventory(1024)
	original, err := NewCBSUpdateStateIndex(inputs)
	if err != nil {
		t.Fatal(err)
	}
	current := original
	retained := []*CBSUpdateStateIndex{original}
	counts := []int{0}
	for i, input := range inputs {
		current, err = current.WithIntendedStates([]CBSUpdateIntentChange{{Identity: input.Manifest.Identity, IntendedState: CBSStateStaged}})
		if err != nil {
			t.Fatal(err)
		}
		current, err = current.WithPublishedUpdates(input.Manifest.Identity, map[string]uint32{"feature": CBSStateAbsent})
		if err != nil {
			t.Fatal(err)
		}
		if (i+1)%32 == 0 {
			retained = append(retained, current)
			counts = append(counts, i+1)
		}
	}
	for n, snapshot := range retained {
		if len(snapshot.PackageIntendedStates()) != len(inputs) {
			t.Fatal("lost inventory")
		}
		for i, input := range inputs {
			wantPackage, wantUpdate := CBSStateInstalled, CBSStateInstalled
			if i < counts[n] {
				wantPackage, wantUpdate = CBSStateStaged, CBSStateAbsent
			}
			state, err := snapshot.PackageIntendedState(input.Manifest.Identity)
			if err != nil || state != wantPackage {
				t.Fatalf("snapshot %d package %d: %#x %v", n, i, state, err)
			}
			update, err := snapshot.UpdateState(input.Manifest.Identity, "feature")
			if err != nil || update.RawState != wantUpdate {
				t.Fatalf("snapshot %d update %d: %+v %v", n, i, update, err)
			}
		}
	}
	// A multi-package update touches shared buckets without modifying retained views.
	changes := make([]CBSUpdateIntentChange, len(inputs))
	for i, input := range inputs {
		changes[i] = CBSUpdateIntentChange{Identity: input.Manifest.Identity, IntendedState: CBSStateAbsent}
	}
	next, err := current.WithIntendedStates(changes)
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range inputs {
		old, _ := current.PackageIntendedState(input.Manifest.Identity)
		value, _ := next.PackageIntendedState(input.Manifest.Identity)
		if old != CBSStateStaged || value != CBSStateAbsent {
			t.Fatal("batch mutated source snapshot")
		}
	}
}

func BenchmarkCBSPublishLargeInventory(b *testing.B) {
	inputs := cbsSnapshotInventory(60000)
	index, err := NewCBSUpdateStateIndex(inputs)
	if err != nil {
		b.Fatal(err)
	}
	updates := map[string]uint32{"feature": CBSStateStaged}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		next, err := index.WithPublishedUpdates(inputs[i%len(inputs)].Manifest.Identity, updates)
		if err != nil {
			b.Fatal(err)
		}
		index = next
	}
}
