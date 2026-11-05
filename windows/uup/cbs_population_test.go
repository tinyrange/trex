package uup

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func populationRequest(t *testing.T, m *AssemblyManifest, state uint32) CBSOrdinaryRequest {
	t.Helper()
	name, err := cbsPackageName(m.Identity)
	if err != nil {
		t.Fatal(err)
	}
	return CBSOrdinaryRequest{Identity: m.Identity, Owner: name, State: state, Integration: 2, Ceiling: CBSStateUnspecified}
}

func populationPolicy() CBSOrdinaryPopulationPolicy {
	return CBSOrdinaryPopulationPolicy{
		WorkLimit:     1000,
		Applicability: func(AssemblyIdentity, *CBSUpdateStateIndex) (uint32, error) { return CBSStateInstalled, nil },
		PopulateMUM: func(AssemblyIdentity, *CBSUpdateStateIndex, CBSExecutionAction) (CBSOrdinaryMUMRequests, error) {
			return CBSOrdinaryMUMRequests{}, nil
		},
	}
}

func TestCBSOrdinaryPopulationPublicationAndDepthFirstOrder(t *testing.T) {
	root := cbsIntentManifest(t, "Root", "neutral", `<update name="first"/><update name="late"/>`)
	child := cbsIntentManifest(t, "Child", "neutral", `<update name="remote"><applicable disposition="detect"><detectUpdate><parent name="late"/></detectUpdate></applicable></update>`)
	second := cbsIntentManifest(t, "Second", "neutral", `<update name="f"/>`)
	grand := cbsIntentManifest(t, "Grand", "neutral", `<update name="f"/>`)
	old := cbsIntentManifest(t, "Old", "neutral", `<update name="f"/>`)
	deferred := cbsIntentManifest(t, "Deferred", "neutral", `<update name="f"/>`)
	nextRoot := cbsIntentManifest(t, "NextRoot", "neutral", `<update name="f"/>`)
	root.References = []AssemblyReference{{Kind: "package", Identity: child.Identity, UpdateName: "first", Integrate: "hidden"}, {Kind: "package", Identity: second.Identity, UpdateName: "late"}}
	child.References = []AssemblyReference{{Kind: "package", Identity: grand.Identity, UpdateName: "remote"}}
	inputs := []CBSPackageIntent{{Manifest: root, IntendedState: 0x40}, {Manifest: child, Parents: []AssemblyIdentity{root.Identity}}}
	for _, m := range []*AssemblyManifest{second, grand, old, deferred, nextRoot} {
		inputs = append(inputs, CBSPackageIntent{Manifest: m})
	}
	index, err := NewCBSUpdateStateIndex(inputs)
	if err != nil {
		t.Fatal(err)
	}
	index, err = index.WithPublishedUpdates(root.Identity, map[string]uint32{"late": 0x40})
	if err != nil {
		t.Fatal(err)
	}
	// Prime dependent memo with the obsolete, capped publication. Merely raising
	// Root cannot repair it: correct publication order must do that explicitly.
	if v, err := index.UpdateState(child.Identity, "remote"); err != nil || v.RawState != 0x40 {
		t.Fatal(v, err)
	}
	policy := populationPolicy()
	var admitted, notified []string
	policy.Watch = ordinaryWatchPolicy()
	policy.Watch.Dependents = func(e CBSOrdinaryExecution, _ *CBSUpdateStateIndex) ([]CBSOrdinaryRequest, error) {
		notified = append(notified, e.Identity.Name)
		return nil, nil
	}
	var snapshots []*CBSUpdateStateIndex
	policy.Applicability = func(id AssemblyIdentity, snapshot *CBSUpdateStateIndex) (uint32, error) {
		admitted = append(admitted, id.Name)
		snapshots = append(snapshots, snapshot)
		if id.ExactKey() == child.Identity.ExactKey() {
			v, err := snapshot.UpdateState(root.Identity, "late")
			if err != nil || v.RawState != 0x70 {
				t.Fatalf("child admitted before all parent updates: %+v %v", v, err)
			}
		}
		return 0x70, nil
	}
	policy.PopulateMUM = func(id AssemblyIdentity, snapshot *CBSUpdateStateIndex, action CBSExecutionAction) (CBSOrdinaryMUMRequests, error) {
		if id.ExactKey() != root.Identity.ExactKey() {
			return CBSOrdinaryMUMRequests{}, nil
		}
		// MUM runs after admission but before this package's update publications.
		v, err := snapshot.UpdateState(root.Identity, "late")
		if err != nil || v.RawState != 0x40 || v.IntendedState != 0x40 {
			t.Fatal(v, err)
		}
		a, b := populationRequest(t, old, 0x40), populationRequest(t, deferred, 0x40)
		a.SkipMUM, b.SkipMUM = true, true
		return CBSOrdinaryMUMRequests{BeforeUpdates: []CBSOrdinaryRequest{a}, Deferred: []CBSOrdinaryRequest{b}}, nil
	}
	result, err := PlanCBSOrdinaryPopulation(index, nil, []CBSOrdinaryRequest{populationRequest(t, root, 0x70), populationRequest(t, nextRoot, 0x70)}, policy)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"Root", "Old", "Child", "Grand", "Second", "NextRoot", "Deferred"}
	if !reflect.DeepEqual(admitted, want) || result.Admissions != len(want) {
		t.Fatal(admitted, result.Admissions)
	}
	wantRegistered := []string{"Old", "Root", "Child", "Grand", "Second", "NextRoot", "Deferred"}
	var registered []string
	for _, entry := range result.Executions {
		registered = append(registered, entry.Identity.Name)
	}
	if !reflect.DeepEqual(registered, wantRegistered) || !reflect.DeepEqual(notified, wantRegistered) {
		t.Fatal("registration/watch order", registered, notified)
	}
	if result.Executions[2].Updates["remote"] != 0x70 || result.Executions[2].Owners[0].Integration != 3 {
		t.Fatal(result.Executions[2])
	}
	for _, snapshot := range []*CBSUpdateStateIndex{index, snapshots[0], snapshots[1]} {
		v, err := snapshot.UpdateState(root.Identity, "late")
		if err != nil || v.RawState != 0x40 {
			t.Fatal("retained snapshot changed", v, err)
		}
	}
	// The returned execution maps are independent of the returned index.
	result.Executions[1].Updates["late"] = 0
	if v, err := result.Index.UpdateState(root.Identity, "late"); err != nil || v.RawState != 0x70 {
		t.Fatal(v, err)
	}
}

func TestCBSOrdinaryPopulationOwnerReplacementAndOriginalAction(t *testing.T) {
	m := cbsIntentManifest(t, "Root", "neutral", `<update name="f"/>`)
	index, err := NewCBSUpdateStateIndex([]CBSPackageIntent{{Manifest: m, IntendedState: 0x70}})
	if err != nil {
		t.Fatal(err)
	}
	a, b := populationRequest(t, m, 0x40), populationRequest(t, m, 0x70)
	a.Integration, b.Integration = 3, 4
	policy := populationPolicy()
	mum := 0
	policy.PopulateMUM = func(AssemblyIdentity, *CBSUpdateStateIndex, CBSExecutionAction) (CBSOrdinaryMUMRequests, error) {
		mum++
		return CBSOrdinaryMUMRequests{}, nil
	}
	result, err := PlanCBSOrdinaryPopulation(index, nil, []CBSOrdinaryRequest{a, b, a}, policy)
	if err != nil {
		t.Fatal(err)
	}
	e := result.Executions[0]
	// A processed installed -> staged downgrade dispatches reinstall (4).
	// Its next merge compares with the preceding target, giving install (3).
	if mum != 3 || !e.MUMPopulated || e.MUMPasses != 3 || e.IntendedState != 0x40 || !e.Dirty || len(e.Owners) != 1 || e.Owners[0].State != 0x40 || e.Owners[0].Integration != 3 {
		t.Fatal(mum, e)
	}
	// A high store owner from a DIFFERENT owner still dominates the replacement;
	// untouched store owners must not become execution owners for persistence.
	other := cbsIntentManifest(t, "Other", "neutral", "")
	otherName, _ := cbsPackageName(other.Identity)
	name, _ := cbsPackageName(m.Identity)
	stores := []CBSPackageOwnerIntent{{Package: name, Owner: name, Integration: 2, State: 0x70}, {Package: name, Owner: otherName, Integration: 2, State: 0x70}}
	result, err = PlanCBSOrdinaryPopulation(index, stores, []CBSOrdinaryRequest{a}, policy)
	if err != nil {
		t.Fatal(err)
	}
	e = result.Executions[0]
	if e.IntendedState != 0x70 || e.Dirty || len(e.Owners) != 1 || e.Owners[0].State != 0x40 || stores[0].State != 0x70 {
		t.Fatal(e, stores)
	}
}

func TestCBSOrdinaryPopulationMUMLifecycleAndDirtyNormalization(t *testing.T) {
	for _, tc := range []struct {
		original uint32
		requests []uint32
		mum      int
		dirty    bool
	}{
		{0, []uint32{0x40, 0x70, 0x40}, 3, true},
		{0x50, []uint32{0x40, 0x50}, 0, false},
		{0x80, []uint32{0x70}, 0, true},
		{0x20, []uint32{0x70}, 1, true},
	} {
		m := cbsIntentManifest(t, "Root", "neutral", `<update name="f"/>`)
		index, err := NewCBSUpdateStateIndex([]CBSPackageIntent{{Manifest: m, IntendedState: tc.original}})
		if err != nil {
			t.Fatal(err)
		}
		roots := []CBSOrdinaryRequest{}
		for _, state := range tc.requests {
			roots = append(roots, populationRequest(t, m, state))
		}
		policy := populationPolicy()
		calls := 0
		policy.PopulateMUM = func(AssemblyIdentity, *CBSUpdateStateIndex, CBSExecutionAction) (CBSOrdinaryMUMRequests, error) {
			calls++
			return CBSOrdinaryMUMRequests{}, nil
		}
		result, err := PlanCBSOrdinaryPopulation(index, nil, roots, policy)
		if err != nil {
			t.Fatal(err)
		}
		if calls != tc.mum || result.Executions[0].Dirty != tc.dirty {
			t.Fatal(tc, calls, result.Executions[0])
		}
	}
}

func TestCBSOrdinaryPopulationFailureAtomicAndBounded(t *testing.T) {
	m := cbsIntentManifest(t, "Root", "neutral", `<update name="f"/>`)
	missing := cbsIntentManifest(t, "Missing", "neutral", "")
	m.References = []AssemblyReference{{Kind: "package", Identity: missing.Identity, UpdateName: "f"}}
	index, err := NewCBSUpdateStateIndex([]CBSPackageIntent{{Manifest: m}})
	if err != nil {
		t.Fatal(err)
	}
	root := populationRequest(t, m, 0x70)
	policy := populationPolicy()
	if p, err := PlanCBSOrdinaryPopulation(index, nil, []CBSOrdinaryRequest{root}, policy); err == nil || p != nil {
		t.Fatal("missing reference accepted", p, err)
	}
	policy.OmittedReferences = []AssemblyIdentity{missing.Identity}
	if _, err := PlanCBSOrdinaryPopulation(index, nil, []CBSOrdinaryRequest{root}, policy); err != nil {
		t.Fatal(err)
	}
	// Errors after admission/publication cannot expose a partial plan.
	policy.WorkLimit = 2
	if p, err := PlanCBSOrdinaryPopulation(index, nil, []CBSOrdinaryRequest{root}, policy); err == nil || p != nil {
		t.Fatal(p, err)
	}
	policy = populationPolicy()
	sentinel := errors.New("unresolved MUM policy")
	policy.PopulateMUM = func(AssemblyIdentity, *CBSUpdateStateIndex, CBSExecutionAction) (CBSOrdinaryMUMRequests, error) {
		return CBSOrdinaryMUMRequests{}, sentinel
	}
	if p, err := PlanCBSOrdinaryPopulation(index, nil, []CBSOrdinaryRequest{root}, policy); !errors.Is(err, sentinel) || p != nil {
		t.Fatal(p, err)
	}
	if index.graph.packages.get(m.Identity.ExactKey()).input.IntendedState != 0 || len(index.graph.memo) != 0 || index.graph.packages.get(m.Identity.ExactKey()).published.count != 0 {
		t.Fatal("input index mutated")
	}
	// Self references must hit the shared work bound instead of unbounded recursion.
	cycle := cbsIntentManifest(t, "Cycle", "neutral", `<update name="f"/>`)
	cycle.References = []AssemblyReference{{Kind: "package", Identity: cycle.Identity, UpdateName: "f"}}
	cyclic, err := NewCBSUpdateStateIndex([]CBSPackageIntent{{Manifest: cycle}})
	if err != nil {
		t.Fatal(err)
	}
	policy = populationPolicy()
	policy.WorkLimit = 30
	if p, err := PlanCBSOrdinaryPopulation(cyclic, nil, []CBSOrdinaryRequest{populationRequest(t, cycle, 0x70)}, policy); err == nil || p != nil || !strings.Contains(err.Error(), "work limit") {
		t.Fatal(p, err)
	}
}
