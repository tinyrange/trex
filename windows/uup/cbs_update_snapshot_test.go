package uup

import "testing"

func TestCBSUpdateSnapshotChangeInvalidatesTransitiveMemo(t *testing.T) {
	parent := cbsIntentManifest(t, "Parent", "neutral", `<update name="feature"/>`)
	middle := cbsIntentManifest(t, "Middle", "neutral", `<update name="feature"><applicable disposition="detect"><detectUpdate><parent name="feature"/></detectUpdate></applicable></update>`)
	leaf := cbsIntentManifest(t, "Leaf", "neutral", `<update name="feature"><applicable disposition="detect"><detectUpdate><parent name="feature"/></detectUpdate></applicable></update>`)
	old, err := NewCBSUpdateStateIndex([]CBSPackageIntent{
		{Manifest: parent, IntendedState: 0x70},
		{Manifest: middle, IntendedState: 0x70, Parents: []AssemblyIdentity{parent.Identity}},
		{Manifest: leaf, IntendedState: 0x70, Parents: []AssemblyIdentity{middle.Identity}},
	})
	if err != nil {
		t.Fatal(err)
	}
	check := func(index *CBSUpdateStateIndex, want uint32) {
		t.Helper()
		got, err := index.UpdateState(leaf.Identity, "feature")
		if err != nil || got != (CBSUpdateState{want, want}) {
			t.Fatal(got, want, err)
		}
	}
	check(old, 0x70) // Prime the entire transitive memo before replacing the source.
	next, err := old.WithIntendedStates([]CBSUpdateIntentChange{{parent.Identity, 0x40}})
	if err != nil {
		t.Fatal(err)
	}
	check(next, 0x40)
	check(old, 0x70)
	third, err := next.WithIntendedStates([]CBSUpdateIntentChange{{parent.Identity, 0x50}})
	if err != nil {
		t.Fatal(err)
	}
	check(third, 0x50)
	check(next, 0x40)
	check(old, 0x70)
	for _, changes := range [][]CBSUpdateIntentChange{
		{{parent.Identity, 0x20}, {middle.Identity, 0x60}},
		{{parent.Identity, 0x20}, {parent.Identity, 0x70}},
		{{AssemblyIdentity{Name: "missing"}, 0x70}},
	} {
		if result, err := old.WithIntendedStates(changes); err == nil || result != nil {
			t.Fatal("accepted invalid snapshot replacement", result, err)
		}
		check(old, 0x70)
	}
}

func TestCBSPublishedUpdateOverridesMetadataButNotDirectApplicability(t *testing.T) {
	m := cbsIntentManifest(t, "Parent", "neutral", `<update name="source"/><update name="dependent"><applicable disposition="detect"><detectUpdate><update name="source"/></detectUpdate></applicable></update>`)
	child := cbsIntentManifest(t, "Child", "neutral", `<update name="remote"><applicable disposition="detect"><detectUpdate><parent name="source"/></detectUpdate></applicable></update>`)
	old, err := NewCBSUpdateStateIndex([]CBSPackageIntent{{Manifest: m, IntendedState: 0x40}, {Manifest: child, IntendedState: 0x70, Parents: []AssemblyIdentity{m.Identity}}})
	if err != nil {
		t.Fatal(err)
	}
	check := func(index *CBSUpdateStateIndex, id AssemblyIdentity, name string, direct bool, raw, capped uint32) {
		t.Helper()
		var got CBSUpdateState
		var err error
		if direct {
			got, err = index.ApplicableUpdateState(id, name)
		} else {
			got, err = index.UpdateState(id, name)
		}
		if err != nil || got != (CBSUpdateState{raw, capped}) {
			t.Fatalf("%s direct=%v got=%+v want=%x/%x err=%v", name, direct, got, raw, capped, err)
		}
	}
	check(old, m.Identity, "dependent", false, 0x70, 0x40)
	input := map[string]uint32{"SOURCE": 0x40}
	published, err := old.WithPublishedUpdates(m.Identity, input)
	if err != nil {
		t.Fatal(err)
	}
	input["SOURCE"] = 0x70
	check(published, m.Identity, "source", false, 0x40, 0x40)
	check(published, m.Identity, "source", true, 0x70, 0x40)
	check(published, m.Identity, "dependent", true, 0x40, 0x40)
	raised, err := published.WithIntendedStates([]CBSUpdateIntentChange{{m.Identity, 0x70}})
	if err != nil {
		t.Fatal(err)
	}
	// Raising the package must not silently raise a previously published target.
	check(raised, m.Identity, "source", false, 0x40, 0x40)
	check(raised, m.Identity, "dependent", false, 0x40, 0x40)
	check(raised, child.Identity, "remote", false, 0x40, 0x40)
	check(raised, m.Identity, "source", true, 0x70, 0x70)
	// Explicit re-publication changes transitive detections but not old snapshots.
	advanced, err := raised.WithPublishedUpdates(m.Identity, map[string]uint32{"source": 0x70})
	if err != nil {
		t.Fatal(err)
	}
	check(advanced, m.Identity, "dependent", false, 0x70, 0x70)
	check(advanced, child.Identity, "remote", false, 0x70, 0x70)
	check(raised, m.Identity, "dependent", false, 0x40, 0x40)
	check(old, m.Identity, "dependent", false, 0x70, 0x40)
	cleared, err := raised.WithPublishedUpdates(m.Identity, map[string]uint32{"source": CBSStateUnspecified})
	if err != nil {
		t.Fatal(err)
	}
	check(cleared, m.Identity, "source", false, 0x70, 0x70)
	for _, bad := range []map[string]uint32{{"source": 0x60}, {"source": 0x40, "SOURCE": 0x70}, {"missing": 0x70}} {
		if result, err := raised.WithPublishedUpdates(m.Identity, bad); err == nil || result != nil {
			t.Fatal("accepted malformed publication", result, err)
		}
		check(raised, m.Identity, "source", false, 0x40, 0x40)
	}
}
