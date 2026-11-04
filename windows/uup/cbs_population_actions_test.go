package uup

import (
	"reflect"
	"testing"
)

// These sequences distinguish Initialize's installed restaging, Merge's use of
// the *processed* predecessor versus original store state, and skip-MUM from an
// action-independent once-only latch. They exercise the full admission planner.
func TestCBSOrdinaryPopulationMUMActionSequences(t *testing.T) {
	for _, tc := range []struct {
		name      string
		original  uint32
		requests  []uint32
		skip      []bool
		actions   []CBSExecutionAction
		last      CBSExecutionAction
		processed bool
	}{
		{"initial-installed", 0x70, []uint32{0x70}, nil, []CBSExecutionAction{CBSActionInstall}, CBSActionInstall, true},
		{"equal-merge-clears", 0x70, []uint32{0x70, 0x70}, nil, []CBSExecutionAction{CBSActionInstall}, CBSActionNone, false},
		{"merge-after-clear-uses-original", 0, []uint32{0x70, 0x70, 0x70}, nil, []CBSExecutionAction{CBSActionInstall, CBSActionInstall}, CBSActionInstall, true},
		{"processed-down-up", 0x70, []uint32{0x40, 0x70}, nil, []CBSExecutionAction{CBSActionUninstall, CBSActionInstall}, CBSActionInstall, true},
		{"skipped-down-up", 0x70, []uint32{0x40, 0x70}, []bool{true, false}, nil, CBSActionNone, false},
		{"skipped-up-down", 0, []uint32{0x70, 0x40}, []bool{true, false}, []CBSExecutionAction{CBSActionStage}, CBSActionStage, true},
		{"reinstall-unresolve", 0x70, []uint32{0}, nil, []CBSExecutionAction{CBSActionUninstallUnstageUnresolve}, CBSActionUninstallUnstageUnresolve, true},
		{"reinstall-unstage", 0x70, []uint32{0x20}, nil, []CBSExecutionAction{CBSActionUninstallUnstage}, CBSActionUninstallUnstage, true},
		{"unstage-not-mum", 0x40, []uint32{0x20}, nil, nil, CBSActionUnstage, false},
		{"unstage-unresolve-not-mum", 0x40, []uint32{0}, nil, nil, CBSActionUnstageUnresolve, false},
		{"unresolve-not-mum", 0x20, []uint32{0}, nil, nil, CBSActionUnresolve, false},
		{"resolve-not-mum", 0, []uint32{0x20}, nil, nil, CBSActionResolve, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := cbsIntentManifest(t, "Root", "neutral", "")
			index, err := NewCBSUpdateStateIndex([]CBSPackageIntent{{Manifest: m, IntendedState: tc.original}})
			if err != nil {
				t.Fatal(err)
			}
			var requests []CBSOrdinaryRequest
			for i, state := range tc.requests {
				r := populationRequest(t, m, state)
				if tc.skip != nil {
					r.SkipMUM = tc.skip[i]
				}
				requests = append(requests, r)
			}
			var actions []CBSExecutionAction
			policy := populationPolicy()
			policy.PopulateMUM = func(_ AssemblyIdentity, _ *CBSUpdateStateIndex, action CBSExecutionAction) (CBSOrdinaryMUMRequests, error) {
				actions = append(actions, action)
				return CBSOrdinaryMUMRequests{}, nil
			}
			result, err := PlanCBSOrdinaryPopulation(index, nil, requests, policy)
			if err != nil {
				t.Fatal(err)
			}
			e := result.Executions[0]
			if !reflect.DeepEqual(actions, tc.actions) || e.Action != tc.last || e.MUMProcessed != tc.processed || e.MUMPasses != len(actions) || e.MUMPopulated != (len(actions) != 0) {
				t.Fatal(actions, e)
			}
		})
	}
}

func TestCBSOrdinaryPopulationMUMRechecksAfterRecursiveSupersedence(t *testing.T) {
	for _, skip := range []bool{false, true} {
		m := cbsIntentManifest(t, "Root", "neutral", "")
		index, err := NewCBSUpdateStateIndex([]CBSPackageIntent{{Manifest: m, IntendedState: 0x70}})
		if err != nil {
			t.Fatal(err)
		}
		var actions []CBSExecutionAction
		var snapshots []*CBSUpdateStateIndex
		policy := populationPolicy()
		policy.PopulateMUM = func(_ AssemblyIdentity, snapshot *CBSUpdateStateIndex, action CBSExecutionAction) (CBSOrdinaryMUMRequests, error) {
			actions = append(actions, action)
			snapshots = append(snapshots, snapshot)
			if action != CBSActionInstall {
				return CBSOrdinaryMUMRequests{}, nil
			}
			r := populationRequest(t, m, 0x40)
			r.SkipMUM = skip
			return CBSOrdinaryMUMRequests{BeforeUpdates: []CBSOrdinaryRequest{r}}, nil
		}
		// Register the execution before testing recursive merges. First-time
		// admission registers only after MUM recursion, so that distinct case
		// needs multiple execution objects rather than a merge.
		result, err := PlanCBSOrdinaryPopulation(index, nil, []CBSOrdinaryRequest{populationRequest(t, m, 0x40), populationRequest(t, m, 0x70)}, policy)
		if err != nil {
			t.Fatal(err)
		}
		e := result.Executions[0]
		// Without skip the nested admission performs reinstall. With skip the
		// outer ProcessMumServicing must recheck and perform it after recursion.
		if !reflect.DeepEqual(actions, []CBSExecutionAction{CBSActionUninstall, CBSActionInstall, CBSActionUninstall}) || e.MUMPasses != 3 || !e.MUMProcessed || e.IntendedState != 0x40 || e.Action != CBSActionUninstall {
			t.Fatal(skip, actions, e)
		}
		key := m.Identity.ExactKey()
		if snapshots[0].graph.packages.get(key).input.IntendedState != 0x40 || snapshots[1].graph.packages.get(key).input.IntendedState != 0x70 || snapshots[2].graph.packages.get(key).input.IntendedState != 0x40 {
			t.Fatal("recursive MUM snapshot changed")
		}
	}
}
