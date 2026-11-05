package uup

import "testing"

func TestCBSApplicabilityNativeSupersedence(t *testing.T) {
	identity := cbsIntentManifest(t, "Root", "neutral", "").Identity
	identity.Version = "10.0.26100.10"
	for _, tc := range []struct {
		name, version, language, packageName string
		intended, parent                     uint32
		force, branch                        bool
		want                                 uint32
	}{
		{"newer installed", "10.0.26100.11", "neutral", "Root", 0x70, 0x1000, false, true, 0x50},
		{"newer permanent", "10.0.26100.11", "neutral", "Root", 0x80, 0x70, false, true, 0x50},
		{"forced staged", "10.0.26100.11", "neutral", "Root", 0x70, 0x70, true, true, 0x40},
		{"staged newer", "10.0.26100.11", "neutral", "Root", 0x40, 0x70, false, true, 0x70},
		{"superseded newer", "10.0.26100.11", "neutral", "Root", 0x50, 0x70, false, true, 0x70},
		{"equal", "10.0.26100.10", "neutral", "Root", 0x80, 0x70, false, true, 0x70},
		{"older", "10.0.26100.9", "neutral", "Root", 0x70, 0x70, false, true, 0x70},
		{"higher build lower revision", "10.0.26101.1", "neutral", "Root", 0x70, 0x70, false, true, 0x50},
		{"higher major lower other parts", "11.0.1.1", "neutral", "Root", 0x70, 0x70, false, true, 0x50},
		{"different language", "10.0.26100.11", "en-US", "Root", 0x70, 0x70, false, true, 0x70},
		{"different family", "10.0.26100.11", "neutral", "Other", 0x70, 0x70, false, true, 0x70},
		{"parent staged", "10.0.26100.11", "neutral", "Root", 0x70, 0x40, false, true, 0x40},
		{"parent absent", "10.0.26100.11", "neutral", "Root", 0x70, 0, false, true, 0},
		{"wrong branch", "10.0.26100.11", "neutral", "Root", 0x70, 0x70, true, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := identity
			candidate.Version, candidate.Language, candidate.Name = tc.version, tc.language, tc.packageName
			index, err := NewCBSParentStateIndex([]CBSParentCandidate{{Identity: candidate, IntendedState: tc.intended, Baseline: true}})
			if err != nil {
				t.Fatal(err)
			}
			got, err := index.ApplicableState(identity, CBSApplicability{ParentState: tc.parent, BranchMatches: tc.branch, ForceStageSuperseded: tc.force})
			if err != nil || got != tc.want {
				t.Fatalf("got %#x, %v; want %#x", got, err, tc.want)
			}
		})
	}
}

func TestCBSApplicabilitySearchesPastStagedNewerVersion(t *testing.T) {
	id := cbsIntentManifest(t, "Root", "neutral", "").Identity
	id.Version = "10.0.26100.10"
	installed, staged := id, id
	installed.Version, staged.Version = "10.0.26100.11", "10.0.26100.12"
	index, err := NewCBSParentStateIndex([]CBSParentCandidate{
		{Identity: staged, IntendedState: CBSStateStaged, Baseline: true},
		{Identity: installed, IntendedState: CBSStateInstalled},
	})
	if err != nil {
		t.Fatal(err)
	}
	state, err := index.ApplicableState(id, CBSApplicability{ParentState: CBSStateUnspecified, BranchMatches: true})
	if err != nil || state != CBSStateSuperseded {
		t.Fatalf("got %#x, %v", state, err)
	}
	for _, pending := range []uint32{5, 0x60, 0xffffffff} {
		if state, err := index.ApplicableState(id, CBSApplicability{ParentState: pending, BranchMatches: true}); err == nil || state != 0 {
			t.Fatalf("accepted unresolved parent %#x", pending)
		}
	}
	var missing *CBSParentStateIndex
	if _, err := missing.ApplicableState(id, CBSApplicability{}); err == nil {
		t.Fatal("accepted nil index")
	}
}
