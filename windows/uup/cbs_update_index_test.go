package uup

import "testing"

func TestCBSUpdateSnapshotFeedsRepeatedAdmissions(t *testing.T) {
	parent := cbsIntentManifest(t, "Parent", "neutral", `<update name="feature"/>`)
	wrapper := cbsIntentManifest(t, "Wrapper", "neutral", `<update name="content"><applicable disposition="detect"><detectUpdate><parent name="feature"/></detectUpdate></applicable>`+ownerChild+`</update>`)
	child := cbsIntentManifest(t, "Child", "neutral", "")
	wrapperName, _ := cbsPackageName(wrapper.Identity)
	childName, _ := cbsPackageName(child.Identity)
	inputs := []CBSPackageIntent{
		{Manifest: parent, IntendedState: CBSStateAbsent},
		{Manifest: wrapper, IntendedState: CBSStateInstalled, Parents: []AssemblyIdentity{parent.Identity}},
	}
	var execution []CBSPackageOwnerIntent
	// The incoming owner is re-evaluated at each snapshot. In particular the
	// final downgrade must replace the previous installed request, not MAX it.
	for _, state := range []uint32{0, 0x20, 0x40, 0x70, 0x50, 0x40} {
		inputs[0].IntendedState = state
		index, err := NewCBSUpdateStateIndex(inputs)
		if err != nil {
			t.Fatal(err)
		}
		local, err := index.UpdateState(parent.Identity, "FEATURE")
		if err != nil || local != (CBSUpdateState{0x70, state}) {
			t.Fatalf("parent state %x: local %+v, %v", state, local, err)
		}
		update, err := index.UpdateState(wrapper.Identity, "content")
		if err != nil || update != (CBSUpdateState{state, state}) {
			t.Fatalf("parent state %x: wrapper %+v, %v", state, update, err)
		}
		admission, err := ResolveCBSPackageAdmission(CBSPackageAdmission{
			Identity: child.Identity, ExecutionOwners: execution,
			Owner: wrapperName, RequestedState: update.IntendedState,
			Ceiling: CBSStateUnspecified, ApplicableState: CBSStateInstalled,
		})
		if err != nil || admission.IntendedState != state {
			t.Fatalf("parent state %x: admission %+v, %v", state, admission, err)
		}
		execution = []CBSPackageOwnerIntent{{Package: childName, Owner: wrapperName, Integration: 2, State: admission.EffectiveRequest}}
	}
}

func TestCBSUpdateSnapshotCopiesMutablePolicy(t *testing.T) {
	parent := cbsIntentManifest(t, "Parent", "neutral", `<update name="feature"><selectable disposition="staged"><detectNone default="false"/></selectable></update>`)
	wrapper := cbsIntentManifest(t, "Wrapper", "neutral", `<update name="content"><applicable disposition="detect"><detectUpdate><parent name="feature"/></detectUpdate></applicable></update>`)
	inputs := []CBSPackageIntent{
		{Manifest: parent, IntendedState: CBSStateInstalled, SelectableChoices: map[string]bool{"feature": true}},
		{Manifest: wrapper, IntendedState: CBSStateInstalled, Parents: []AssemblyIdentity{parent.Identity}},
	}
	old, err := NewCBSUpdateStateIndex(inputs)
	if err != nil {
		t.Fatal(err)
	}
	// Mutate caller policy before the old index's first (uncached) evaluation.
	// An index models a snapshot, not whichever slice happens to be current.
	inputs[0].IntendedState = CBSStateSuperseded
	inputs[0].SelectableChoices["feature"] = false
	inputs[1].Parents[0] = wrapper.Identity
	got, err := old.UpdateState(wrapper.Identity, "content")
	if err != nil || got != (CBSUpdateState{0x70, 0x70}) {
		t.Fatal(got, err)
	}
	inputs[1].Parents[0] = parent.Identity
	fresh, err := NewCBSUpdateStateIndex(inputs)
	if err != nil {
		t.Fatal(err)
	}
	got, err = fresh.UpdateState(wrapper.Identity, "content")
	if err != nil || got != (CBSUpdateState{0x40, 0x40}) {
		t.Fatal(got, err)
	}
}

func TestCBSUpdateSnapshotDoesNotRelaxOwnerProjection(t *testing.T) {
	m := cbsIntentManifest(t, "Wrapper", "neutral", `<update name="content">`+ownerChild+`</update>`)
	for _, state := range []uint32{0, 0x20, 0x80} {
		inputs := []CBSPackageIntent{{Manifest: m, IntendedState: state}}
		index, err := NewCBSUpdateStateIndex(inputs)
		if err != nil {
			t.Fatal(err)
		}
		got, err := index.UpdateState(m.Identity, "content")
		if err != nil || got.RawState != CBSStateInstalled || got.IntendedState != min(state, CBSStateInstalled) {
			t.Fatal(got, err)
		}
		if owners, err := PlanCBSPackageOwners(inputs, nil); err == nil || owners != nil {
			t.Fatal("read-only snapshot broadened owner projection", owners, err)
		}
	}
	for _, state := range []uint32{5, 0x60, CBSStateUnspecified} {
		if index, err := NewCBSUpdateStateIndex([]CBSPackageIntent{{Manifest: m, IntendedState: state}}); err == nil || index != nil {
			t.Fatal("accepted unresolved snapshot", state, index, err)
		}
	}
}
