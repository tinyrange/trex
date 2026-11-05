package uup

import (
	"strings"
	"testing"
)

func TestCBSOrdinaryPopulationRejectsUnregisteredRecursiveAdmission(t *testing.T) {
	m := cbsIntentManifest(t, "Root", "neutral", `<update name="f"/>`)
	index, err := NewCBSUpdateStateIndex([]CBSPackageIntent{{Manifest: m}})
	if err != nil {
		t.Fatal(err)
	}
	policy := populationPolicy()
	policy.PopulateMUM = func(id AssemblyIdentity, snapshot *CBSUpdateStateIndex, _ CBSExecutionAction) (CBSOrdinaryMUMRequests, error) {
		// Target publication precedes MUM and must not be confused with insertion
		// into the native execution lookup. A recursive admission here would create
		// a second object, not merge the first object's owners or processed flags.
		if snapshot.graph.packages.get(id.ExactKey()).input.IntendedState != 0x70 {
			t.Fatal("missing session target publication")
		}
		r := populationRequest(t, m, 0x40)
		r.SkipMUM = true
		return CBSOrdinaryMUMRequests{BeforeUpdates: []CBSOrdinaryRequest{r}}, nil
	}
	plan, err := PlanCBSOrdinaryPopulation(index, nil, []CBSOrdinaryRequest{populationRequest(t, m, 0x70)}, policy)
	if plan != nil || err == nil || !strings.Contains(err.Error(), "before execution registration") {
		t.Fatal(plan, err)
	}
	if index.graph.packages.get(m.Identity.ExactKey()).input.IntendedState != 0 || len(index.graph.memo) != 0 {
		t.Fatal("input changed on failure")
	}
}
