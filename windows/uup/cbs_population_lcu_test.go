package uup

import "testing"

func TestCBSLCUSessionRequiresMatchingTaskAndRecordsNotFound(t *testing.T) {
	root := cbsIntentManifest(t, "Package_for_RollupFix", "neutral", "")
	parent := cbsIntentManifest(t, "NewLanguagePack", "neutral", `<update name="edition"/>`)
	missing := cbsIntentManifest(t, "OtherEdition", "neutral", "")
	parent.References = []AssemblyReference{{Kind: "package", Identity: missing.Identity, UpdateName: "edition"}}
	index, err := NewCBSUpdateStateIndex([]CBSPackageIntent{{Manifest: root}, {Manifest: parent}})
	if err != nil {
		t.Fatal(err)
	}
	for _, rootState := range []uint32{CBSStateAbsent, CBSStateStaged, CBSStateSuperseded, CBSStateInstalled} {
		for _, enabled := range []bool{false, true} {
			policy := populationPolicy()
			policy.LCUSession = enabled
			// Session tasks establish the flag before admissions, including a child
			// encountered before the LCU root itself is processed.
			requests := []CBSOrdinaryRequest{populationRequest(t, parent, CBSStateInstalled), populationRequest(t, root, rootState)}
			result, err := PlanCBSOrdinaryPopulation(index, nil, requests, policy)
			valid := enabled && (rootState == CBSStateStaged || rootState == CBSStateInstalled)
			if !valid {
				if err == nil || result != nil {
					t.Fatalf("unjustified optional lookup: %#x %v", rootState, enabled)
				}
				continue
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(result.UnresolvedReferences) != 1 {
				t.Fatalf("lost audit: %+v", result.UnresolvedReferences)
			}
			ref := result.UnresolvedReferences[0]
			if ref.Reason != "lcu-session" || ref.Parent.ExactKey() != parent.Identity.ExactKey() || ref.Package.ExactKey() != missing.Identity.ExactKey() || ref.UpdateName != "edition" || ref.IntendedState != CBSStateInstalled {
				t.Fatalf("wrong optional reference: %+v", ref)
			}
			if len(result.Executions) != 2 {
				t.Fatal("invented missing package admission")
			}
		}
	}
	policy := populationPolicy()
	policy.LCUSession = true
	if _, err := PlanCBSOrdinaryPopulation(index, nil, []CBSOrdinaryRequest{populationRequest(t, parent, CBSStateInstalled)}, policy); err == nil {
		t.Fatal("LCU policy without LCU task")
	}
	if _, err := PlanCBSOrdinaryPopulation(index, nil, []CBSOrdinaryRequest{populationRequest(t, root, CBSStateInstalled), populationRequest(t, missing, CBSStateInstalled)}, policy); err == nil {
		t.Fatal("missing root ignored by LCU policy")
	}
}
