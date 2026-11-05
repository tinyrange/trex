package uup

import "testing"

func TestCBSStoreLoadedChildResolutionIsProvenanceScoped(t *testing.T) {
	parent := cbsIntentManifest(t, "LanguagePack", "neutral", `<update name="edition"/>`)
	missing := cbsIntentManifest(t, "OtherEdition", "neutral", "")
	parent.References = []AssemblyReference{{Kind: "package", Identity: missing.Identity, UpdateName: "edition", Integrate: "hidden"}}
	index, err := NewCBSUpdateStateIndex([]CBSPackageIntent{{Manifest: parent, IntendedState: CBSStateInstalled}})
	if err != nil {
		t.Fatal(err)
	}
	for _, storeLoaded := range []bool{false, true} {
		policy := populationPolicy()
		policy.Applicability = func(AssemblyIdentity, *CBSUpdateStateIndex) (uint32, error) { return CBSStateSuperseded, nil }
		if storeLoaded {
			policy.StoreLoadedPackages = []AssemblyIdentity{parent.Identity}
		}
		result, err := PlanCBSOrdinaryPopulation(index, nil, []CBSOrdinaryRequest{populationRequest(t, parent, CBSStateInstalled)}, policy)
		if !storeLoaded {
			if err == nil || result != nil {
				t.Fatal("nonzero source child silently omitted")
			}
		} else {
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Executions) != 1 || result.Executions[0].Updates["edition"] != CBSStateSuperseded {
				t.Fatalf("unexpected store result: %+v", result)
			}
		}
	}
	policy := populationPolicy()
	for _, ids := range [][]AssemblyIdentity{{parent.Identity, parent.Identity}, {missing.Identity}} {
		policy.StoreLoadedPackages = ids
		if result, err := PlanCBSOrdinaryPopulation(index, nil, []CBSOrdinaryRequest{populationRequest(t, parent, CBSStateInstalled)}, policy); err == nil || result != nil {
			t.Fatal("invalid provenance accepted")
		}
	}
	// The same provenance is not permission to omit an unresolved root.
	policy.StoreLoadedPackages = []AssemblyIdentity{parent.Identity}
	if result, err := PlanCBSOrdinaryPopulation(index, nil, []CBSOrdinaryRequest{populationRequest(t, missing, CBSStateInstalled)}, policy); err == nil || result != nil {
		t.Fatal("unresolved root omitted")
	}
	// Available children still receive owners; provenance does not prune them.
	available, err := NewCBSUpdateStateIndex([]CBSPackageIntent{{Manifest: parent, IntendedState: CBSStateInstalled}, {Manifest: missing}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := PlanCBSOrdinaryPopulation(available, nil, []CBSOrdinaryRequest{populationRequest(t, parent, CBSStateInstalled)}, policy)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Executions) != 2 || result.Executions[1].IntendedState != CBSStateInstalled || len(result.Executions[1].Owners) != 1 {
		t.Fatalf("available child pruned: %+v", result)
	}
}
