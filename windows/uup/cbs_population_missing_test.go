package uup

import "testing"

func TestCBSOrdinaryOptionalMissingReferenceRequiresAbsentTarget(t *testing.T) {
	parent := cbsIntentManifest(t, "Wrapper", "neutral", `<update name="f"/>`)
	missing := cbsIntentManifest(t, "Unavailable", "neutral", "")
	parent.References = []AssemblyReference{{Kind: "package", Identity: missing.Identity, UpdateName: "f"}}
	index, err := NewCBSUpdateStateIndex([]CBSPackageIntent{{Manifest: parent, IntendedState: CBSStateStaged}})
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []uint32{CBSStateAbsent, CBSStateStaged, CBSStateInstalled} {
		for _, optional := range []bool{false, true} {
			policy := populationPolicy()
			policy.AllowAbsentReferences = optional
			policy.Applicability = func(AssemblyIdentity, *CBSUpdateStateIndex) (uint32, error) { return target, nil }
			result, err := PlanCBSOrdinaryPopulation(index, nil, []CBSOrdinaryRequest{populationRequest(t, parent, CBSStateInstalled)}, policy)
			if optional && target == CBSStateAbsent {
				if err != nil || result == nil {
					t.Fatalf("optional absent: %v", err)
				}
			} else if err == nil || result != nil {
				t.Fatalf("accepted unresolved target %#x optional=%v", target, optional)
			}
		}
	}
}

func TestCBSSinglePackageQueryPreservesSnapshot(t *testing.T) {
	m := cbsIntentManifest(t, "Package", "neutral", "")
	index, err := NewCBSUpdateStateIndex([]CBSPackageIntent{{Manifest: m, IntendedState: CBSStateStaged}})
	if err != nil {
		t.Fatal(err)
	}
	next, err := index.WithIntendedStates([]CBSUpdateIntentChange{{Identity: m.Identity, IntendedState: CBSStateInstalled}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		index *CBSUpdateStateIndex
		want  uint32
	}{{index, CBSStateStaged}, {next, CBSStateInstalled}} {
		got, err := tc.index.PackageIntendedState(m.Identity)
		if err != nil || got != tc.want {
			t.Fatalf("snapshot state %#x, %v", got, err)
		}
	}
	absent := m.Identity
	absent.Version = "99.0.0.0"
	if _, err := next.PackageIntendedState(absent); err == nil {
		t.Fatal("unknown package treated as absent")
	}
}
