package uup

import "testing"

func TestCBSOrdinaryAbsentSkipPreservesIndependentChildOrder(t *testing.T) {
	absent := cbsIntentManifest(t, "AbsentEdition", "neutral", `<update name="child"/>`)
	first := cbsIntentManifest(t, "Driver", "neutral", "")
	shared := cbsIntentManifest(t, "Shared", "neutral", "")
	absent.References = []AssemblyReference{{Kind: "package", Identity: shared.Identity, UpdateName: "child", Integrate: "hidden"}}
	index, err := NewCBSUpdateStateIndex([]CBSPackageIntent{{Manifest: absent}, {Manifest: first}, {Manifest: shared}})
	if err != nil {
		t.Fatal(err)
	}
	policy := populationPolicy()
	policy.Applicability = func(id AssemblyIdentity, _ *CBSUpdateStateIndex) (uint32, error) {
		if id.ExactKey() == absent.Identity.ExactKey() {
			return CBSStateAbsent, nil
		}
		return CBSStateInstalled, nil
	}
	result, err := PlanCBSOrdinaryPopulation(index, nil, []CBSOrdinaryRequest{
		populationRequest(t, absent, CBSStateStaged),
		populationRequest(t, first, CBSStateStaged),
		populationRequest(t, shared, CBSStateStaged),
	}, policy)
	if err != nil {
		t.Fatal(err)
	}
	if result.Admissions != 2 || len(result.Executions) != 2 || result.Executions[0].Identity.Name != "Driver" || result.Executions[1].Identity.Name != "Shared" {
		t.Fatalf("absent branch changed execution order: %+v", result)
	}
	if len(result.Executions[1].Owners) != 1 || result.Executions[1].Owners[0].State != CBSStateStaged {
		t.Fatalf("skipped branch leaked an owner: %+v", result.Executions[1])
	}
	if state, err := index.PackageIntendedState(shared.Identity); err != nil || state != CBSStateAbsent {
		t.Fatal("input changed", state, err)
	}
}

func TestCBSOrdinaryAbsentRequestRetainsOtherOwner(t *testing.T) {
	m := cbsIntentManifest(t, "Shared", "neutral", "")
	other := cbsIntentManifest(t, "Other", "neutral", "")
	index, err := NewCBSUpdateStateIndex([]CBSPackageIntent{{Manifest: m}})
	if err != nil {
		t.Fatal(err)
	}
	request := populationRequest(t, m, CBSStateAbsent)
	owner := populationRequest(t, other, CBSStateStaged).Owner
	stores := []CBSPackageOwnerIntent{{Package: request.Owner, Owner: owner, State: CBSStateStaged, Integration: 2}}
	result, err := PlanCBSOrdinaryPopulation(index, stores, []CBSOrdinaryRequest{request}, populationPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Executions) != 1 || result.Executions[0].IntendedState != CBSStateStaged {
		t.Fatalf("other owner was ignored: %+v", result)
	}
}

func TestCBSOrdinaryAbsentSkipDoesNotHideLaterAdmission(t *testing.T) {
	m := cbsIntentManifest(t, "Package", "neutral", `<update name="missing"/>`)
	missing := cbsIntentManifest(t, "Unavailable", "neutral", "")
	m.References = []AssemblyReference{{Kind: "package", Identity: missing.Identity, UpdateName: "missing"}}
	index, err := NewCBSUpdateStateIndex([]CBSPackageIntent{{Manifest: m}})
	if err != nil {
		t.Fatal(err)
	}
	zero, staged := populationRequest(t, m, CBSStateAbsent), populationRequest(t, m, CBSStateStaged)
	result, err := PlanCBSOrdinaryPopulation(index, nil, []CBSOrdinaryRequest{zero}, populationPolicy())
	if err != nil || len(result.Executions) != 0 {
		t.Fatalf("irrelevant child was visited: %+v %v", result, err)
	}
	if result, err := PlanCBSOrdinaryPopulation(index, nil, []CBSOrdinaryRequest{zero, staged}, populationPolicy()); err == nil || result != nil {
		t.Fatal("skipped package suppressed later missing-child failure")
	}
}
