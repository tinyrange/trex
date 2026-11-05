package uup

import (
	"strings"
	"testing"
)

func TestCBSOrdinaryAbsentTargetBypassesCyclicApplicability(t *testing.T) {
	root := cbsIntentManifest(t, "WinPE-WiFi", "neutral", `<update name="self"><applicable disposition="detect"><detectUpdate><update name="other"/></detectUpdate></applicable></update><update name="other"><applicable disposition="detect"><detectUpdate><update name="self"/></detectUpdate></applicable></update>`)
	child := cbsIntentManifest(t, "WiFi-child", "neutral", `<update name="leaf"/>`)
	root.References = []AssemblyReference{{Kind: "package", Identity: child.Identity, UpdateName: "self"}}
	index, err := NewCBSUpdateStateIndex([]CBSPackageIntent{{Manifest: root, IntendedState: CBSStateStaged}, {Manifest: child, IntendedState: CBSStateStaged}})
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []uint32{CBSStateAbsent, CBSStateStaged, CBSStateInstalled} {
		policy := populationPolicy()
		policy.Applicability = func(AssemblyIdentity, *CBSUpdateStateIndex) (uint32, error) { return target, nil }
		result, err := PlanCBSOrdinaryPopulation(index, nil, []CBSOrdinaryRequest{populationRequest(t, root, CBSStateInstalled)}, policy)
		if target != CBSStateAbsent {
			if err == nil || !strings.Contains(err.Error(), "cyclic CBS update") || result != nil {
				t.Fatalf("nonzero cycle accepted: %#x %v", target, err)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Executions) != 2 || result.Executions[0].Updates["self"] != CBSStateAbsent || result.Executions[1].IntendedState != CBSStateAbsent || len(result.Executions[1].Owners) != 1 || result.Executions[1].Owners[0].State != CBSStateAbsent {
			t.Fatalf("absent propagation: %+v", result.Executions)
		}
		value, err := result.Index.UpdateState(root.Identity, "self")
		if err != nil || value.RawState != CBSStateAbsent {
			t.Fatalf("absent publication: %+v %v", value, err)
		}
	}
	// The bypass belongs to execution population, not metadata evaluation.
	if _, err := index.ApplicableUpdateState(root.Identity, "self"); err == nil {
		t.Fatal("source metadata cycle was hidden or mutated")
	}
}
