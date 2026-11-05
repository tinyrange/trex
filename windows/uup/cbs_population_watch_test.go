package uup

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func ordinaryWatchPolicy() *CBSOrdinaryWatchPolicy {
	return &CBSOrdinaryWatchPolicy{
		InitialUpdate: func(_ AssemblyIdentity, _ string, _ uint32, _ *CBSUpdateStateIndex) (CBSOrdinaryUpdateStart, error) {
			return CBSOrdinaryUpdateStart{State: 0, HasDeployments: true}, nil
		},
		Dependents: func(CBSOrdinaryExecution, *CBSUpdateStateIndex) ([]CBSOrdinaryRequest, error) { return nil, nil },
		Satellites: func(CBSOrdinaryExecution, AssemblyIdentity, *CBSUpdateStateIndex) ([]CBSOrdinaryRequest, error) {
			return nil, nil
		},
	}
}

func TestCBSOrdinaryWatchOrderingAndReset(t *testing.T) {
	manifests := map[string]*AssemblyManifest{}
	var inputs []CBSPackageIntent
	for _, name := range []string{"A", "B", "C", "D", "E"} {
		m := cbsIntentManifest(t, name, "neutral", `<update name="f"/>`)
		manifests[name] = m
		inputs = append(inputs, CBSPackageIntent{Manifest: m})
	}
	index, err := NewCBSUpdateStateIndex(inputs)
	if err != nil {
		t.Fatal(err)
	}
	request := func(name string) CBSOrdinaryRequest { return populationRequest(t, manifests[name], 0x70) }
	var notifications, satellites []string
	var retained []CBSOrdinaryExecution
	initialCalls := map[string]int{}
	policy := populationPolicy()
	policy.Watch = ordinaryWatchPolicy()
	policy.Watch.InitialUpdate = func(id AssemblyIdentity, _ string, _ uint32, _ *CBSUpdateStateIndex) (CBSOrdinaryUpdateStart, error) {
		initialCalls[id.Name]++
		return CBSOrdinaryUpdateStart{State: 0, HasDeployments: true}, nil
	}
	policy.Watch.Dependents = func(e CBSOrdinaryExecution, snapshot *CBSUpdateStateIndex) ([]CBSOrdinaryRequest, error) {
		notifications = append(notifications, e.Identity.Name)
		retained = append(retained, cloneCBSOrdinaryExecution(e))
		if e.WatchProcessed {
			t.Fatal("notifier processed before callback")
		}
		// Callback records must not alias planner overlays or published states.
		e.Owners[0].State = 0
		e.Updates["f"] = 0
		delete(e.DirtyUpdates, "f")
		delete(e.UpdateStarts, "f")
		if v, err := snapshot.UpdateState(e.Identity, "f"); err != nil || v.IntendedState != 0x70 {
			t.Fatal(v, err)
		}
		switch e.Identity.Name {
		case "A":
			return []CBSOrdinaryRequest{request("C")}, nil
		case "B":
			return []CBSOrdinaryRequest{request("A")}, nil
		}
		return nil, nil
	}
	policy.Watch.Satellites = func(e CBSOrdinaryExecution, id AssemblyIdentity, snapshot *CBSUpdateStateIndex) ([]CBSOrdinaryRequest, error) {
		satellites = append(satellites, e.Identity.Name+":"+id.Name)
		if e.WatchProcessed {
			t.Fatal("notifier completed before satellites")
		}
		if v, err := snapshot.UpdateState(id, "f"); err != nil || v.IntendedState != 0x70 {
			t.Fatal("scan before admission", v, err)
		}
		if e.Identity.Name == "A" {
			switch id.Name {
			case "C":
				return []CBSOrdinaryRequest{request("D")}, nil
			case "D":
				return []CBSOrdinaryRequest{request("E")}, nil
			}
		}
		return nil, nil
	}
	result, err := PlanCBSOrdinaryPopulation(index, nil, []CBSOrdinaryRequest{request("A"), request("B")}, policy)
	if err != nil {
		t.Fatal(err)
	}
	if result.Admissions != 9 || !reflect.DeepEqual(notifications, []string{"A", "B", "C", "D", "E", "A", "C", "D", "E"}) {
		t.Fatal(result.Admissions, notifications)
	}
	if !reflect.DeepEqual(satellites, []string{"A:C", "A:D", "A:E", "B:A", "A:C", "A:D", "A:E"}) {
		t.Fatal(satellites)
	}
	if !retained[0].DirtyUpdates["f"] || len(retained[5].DirtyUpdates) != 0 || !retained[5].Dirty {
		t.Fatal("dirty bits cleared at wrong time", retained[0], retained[5])
	}
	for _, e := range result.Executions {
		if start, ok := e.UpdateStarts["f"]; !ok || start != (CBSOrdinaryUpdateStart{State: 0, HasDeployments: true}) {
			t.Fatal("initial state lost after repeated notifications or callback mutation", e)
		}
		if !e.WatchProcessed || !e.Dirty || len(e.DirtyUpdates) != 0 || initialCalls[e.Identity.Name] != 1 || e.Owners[0].State != 0x70 || e.Updates["f"] != 0x70 {
			t.Fatal(e, initialCalls)
		}
	}
}

func TestCBSOrdinaryWatchInitialUpdateDirtiness(t *testing.T) {
	for _, tc := range []struct {
		start               uint32
		deployments, notify bool
	}{
		{0x40, false, true}, {0x40, true, false}, {0x50, true, false}, {0x70, true, true},
	} {
		m := cbsIntentManifest(t, "Root", "neutral", `<update name="f"/>`)
		index, err := NewCBSUpdateStateIndex([]CBSPackageIntent{{Manifest: m, IntendedState: 0x40}})
		if err != nil {
			t.Fatal(err)
		}
		policy := populationPolicy()
		policy.Watch = ordinaryWatchPolicy()
		policy.Watch.InitialUpdate = func(AssemblyIdentity, string, uint32, *CBSUpdateStateIndex) (CBSOrdinaryUpdateStart, error) {
			return CBSOrdinaryUpdateStart{State: tc.start, HasDeployments: tc.deployments}, nil
		}
		calls := 0
		policy.Watch.Dependents = func(e CBSOrdinaryExecution, _ *CBSUpdateStateIndex) ([]CBSOrdinaryRequest, error) {
			calls++
			if e.Dirty || !e.DirtyUpdates["f"] {
				t.Fatal(e)
			}
			return nil, nil
		}
		result, err := PlanCBSOrdinaryPopulation(index, nil, []CBSOrdinaryRequest{populationRequest(t, m, 0x40)}, policy)
		if err != nil {
			t.Fatal(err)
		}
		if start, ok := result.Executions[0].UpdateStarts["f"]; !ok || start != (CBSOrdinaryUpdateStart{State: tc.start, HasDeployments: tc.deployments}) {
			t.Fatal("initial state must survive even when no notification is needed", tc, result)
		}
		if (calls == 1) != tc.notify || calls > 1 || result.Executions[0].WatchProcessed != tc.notify {
			t.Fatal(tc, calls, result)
		}
	}
}

func TestCBSOrdinaryWatchFailuresAndCycles(t *testing.T) {
	m := cbsIntentManifest(t, "Root", "neutral", `<update name="f"/>`)
	index, err := NewCBSUpdateStateIndex([]CBSPackageIntent{{Manifest: m}})
	if err != nil {
		t.Fatal(err)
	}
	root := populationRequest(t, m, 0x70)
	policy := populationPolicy()
	sentinel := errors.New("missing watch policy evidence")
	for phase := 0; phase < 5; phase++ {
		policy.Watch = ordinaryWatchPolicy()
		switch phase {
		case 0:
			policy.Watch.Satellites = nil
		case 1:
			policy.Watch.InitialUpdate = func(AssemblyIdentity, string, uint32, *CBSUpdateStateIndex) (CBSOrdinaryUpdateStart, error) {
				return CBSOrdinaryUpdateStart{State: 0x1000}, nil
			}
		case 2:
			policy.Watch.Dependents = func(CBSOrdinaryExecution, *CBSUpdateStateIndex) ([]CBSOrdinaryRequest, error) { return nil, sentinel }
		case 3:
			policy.Watch.Dependents = func(CBSOrdinaryExecution, *CBSUpdateStateIndex) ([]CBSOrdinaryRequest, error) {
				return []CBSOrdinaryRequest{root}, nil
			}
			policy.Watch.Satellites = func(CBSOrdinaryExecution, AssemblyIdentity, *CBSUpdateStateIndex) ([]CBSOrdinaryRequest, error) {
				return nil, sentinel
			}
		case 4:
			policy.WorkLimit = 30
			policy.Watch.Dependents = func(CBSOrdinaryExecution, *CBSUpdateStateIndex) ([]CBSOrdinaryRequest, error) {
				return []CBSOrdinaryRequest{root}, nil
			}
			policy.Watch.Satellites = func(CBSOrdinaryExecution, AssemblyIdentity, *CBSUpdateStateIndex) ([]CBSOrdinaryRequest, error) {
				return []CBSOrdinaryRequest{root}, nil
			}
		}
		result, err := PlanCBSOrdinaryPopulation(index, nil, []CBSOrdinaryRequest{root}, policy)
		if err == nil || result != nil {
			t.Fatal(phase, result, err)
		}
		if (phase == 2 || phase == 3) && !errors.Is(err, sentinel) {
			t.Fatal(err)
		}
		if phase == 4 && !strings.Contains(err.Error(), "work limit") {
			t.Fatal(err)
		}
		if index.graph.packages.get(m.Identity.ExactKey()).input.IntendedState != 0 || len(index.graph.memo) != 0 {
			t.Fatal("input mutated on failure")
		}
	}
}

func TestCBSOrdinaryWatchRejectsUnmodeledDeferredTransactionWork(t *testing.T) {
	root := cbsIntentManifest(t, "Root", "neutral", "")
	child := cbsIntentManifest(t, "Child", "neutral", "")
	index, err := NewCBSUpdateStateIndex([]CBSPackageIntent{{Manifest: root}, {Manifest: child}})
	if err != nil {
		t.Fatal(err)
	}
	policy := populationPolicy()
	policy.Watch = ordinaryWatchPolicy()
	policy.Watch.Dependents = func(e CBSOrdinaryExecution, _ *CBSUpdateStateIndex) ([]CBSOrdinaryRequest, error) {
		if e.Identity.Name == "Root" {
			return []CBSOrdinaryRequest{populationRequest(t, child, 0x70)}, nil
		}
		return nil, nil
	}
	policy.PopulateMUM = func(id AssemblyIdentity, _ *CBSUpdateStateIndex, _ CBSExecutionAction) (CBSOrdinaryMUMRequests, error) {
		if id.Name == "Child" {
			return CBSOrdinaryMUMRequests{Deferred: []CBSOrdinaryRequest{populationRequest(t, root, 0x40)}}, nil
		}
		return CBSOrdinaryMUMRequests{}, nil
	}
	result, err := PlanCBSOrdinaryPopulation(index, nil, []CBSOrdinaryRequest{populationRequest(t, root, 0x70)}, policy)
	if result != nil || err == nil || !strings.Contains(err.Error(), "deferred CBS MUM work during watching") {
		t.Fatal(result, err)
	}
	if index.graph.packages.get(root.Identity.ExactKey()).input.IntendedState != 0 || index.graph.packages.get(child.Identity.ExactKey()).input.IntendedState != 0 {
		t.Fatal("failed watch mutated input")
	}
}
