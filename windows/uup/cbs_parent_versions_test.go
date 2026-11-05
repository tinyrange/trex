package uup

import "testing"

func parentVersionIdentity(version string) AssemblyIdentity {
	return AssemblyIdentity{Name: "Microsoft-Windows-Feature-Package", Version: version,
		ProcessorArchitecture: "amd64", PublicKeyToken: "31bf3856ad364e35", Language: "neutral"}
}

func TestCBSParentVersionDescriptor(t *testing.T) {
	wanted := parentVersionIdentity("10.0.26100.1742")
	for _, tc := range []struct {
		name, version, major, build, revision string
		ignore, want                          bool
	}{
		{"exact", "10.0.26100.1742", "EQ", "EQ", "EQ", false, true},
		{"exact ignore still exact", "10.0.26100.9457", "EQ", "EQ", "EQ", true, false},
		{"range ignore", "10.0.26100.1", "EQ", "EQ", "GE", true, true},
		{"range revision floor", "10.0.26100.1", "EQ", "EQ", "GE", false, false},
		{"higher build lower revision", "10.0.26200.1", "EQ", "GE", "GE", false, true},
		{"higher build unequal revision", "10.0.26200.1", "EQ", "GE", "EQ", false, true},
		{"wrong major", "11.0.26100.1742", "EQ", "GE", "GE", false, false},
		{"higher packed major minor", "10.1.1.1", "GT", "EQ", "EQ", false, true},
		{"equal major strict fails", "10.0.26200.9000", "GT", "GE", "GE", false, false},
		{"equal build strict fails", "10.0.26100.9000", "EQ", "GT", "GE", false, false},
		{"equal build unequal fails", "10.0.26100.9000", "EQ", "NE", "GE", false, false},
		{"unequal build ignores revision", "10.0.26000.1", "EQ", "NE", "GT", false, true},
		{"lower build", "10.0.26000.9000", "EQ", "LT", "LT", false, true},
		{"equal build lower revision", "10.0.26100.1", "EQ", "LE", "LT", false, true},
		{"equal build upper revision", "10.0.26100.9000", "EQ", "LE", "LT", false, false},
		{"revision not equal", "10.0.26100.9000", "EQ", "EQ", "NE", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			index, err := NewCBSParentStateIndex([]CBSParentCandidate{{Identity: parentVersionIdentity(tc.version), IntendedState: 0x70}})
			if err != nil {
				t.Fatal(err)
			}
			state, err := index.Resolve(wanted, CBSParentVersionComparison{tc.major, tc.build, tc.revision, tc.ignore})
			if err != nil || (state == 0x70) != tc.want {
				t.Fatalf("state=%#x err=%v want-match=%v", state, err, tc.want)
			}
		})
	}
}

func TestCBSParentBaselineDescendingRelaxation(t *testing.T) {
	wanted := parentVersionIdentity("10.0.26100.1742")
	old := CBSParentCandidate{Identity: parentVersionIdentity("10.0.26100.1"), IntendedState: 0x70}
	marker := CBSParentCandidate{Identity: wanted, IntendedState: 0x40, Baseline: true}
	for _, tc := range []struct {
		name       string
		candidates []CBSParentCandidate
		descriptor CBSParentVersionComparison
		want       uint32
	}{
		{"baseline permits lower", []CBSParentCandidate{old, marker}, CBSParentVersionComparison{"EQ", "EQ", "GE", false}, 0x70},
		{"order independent", []CBSParentCandidate{marker, old}, CBSParentVersionComparison{"EQ", "EQ", "GE", false}, 0x70},
		{"existing is not Baseline", []CBSParentCandidate{old, {Identity: wanted, IntendedState: 0x40}}, CBSParentVersionComparison{"EQ", "EQ", "GE", false}, 0x40},
		{"superseded Baseline not marker", []CBSParentCandidate{old, {Identity: wanted, IntendedState: 0x50, Baseline: true}}, CBSParentVersionComparison{"EQ", "EQ", "GE", false}, 0x50},
		{"exact Baseline no range", []CBSParentCandidate{old, marker}, CBSParentVersionComparison{"EQ", "EQ", "EQ", false}, 0x40},
		{"exact ignore no range", []CBSParentCandidate{old, marker}, CBSParentVersionComparison{"EQ", "EQ", "EQ", true}, 0x40},
		// LE rejects the newer installed candidate before reaching the marker;
		// relaxation must not restart the descending enumeration.
		{"no restart", []CBSParentCandidate{marker, {Identity: parentVersionIdentity("10.0.26100.9457"), IntendedState: 0x70}}, CBSParentVersionComparison{"EQ", "EQ", "LE", false}, 0x40},
		{"unmatched marker cannot relax", []CBSParentCandidate{old, {Identity: parentVersionIdentity("10.0.26100.100"), IntendedState: 0x40, Baseline: true}}, CBSParentVersionComparison{"EQ", "EQ", "GE", false}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			index, err := NewCBSParentStateIndex(tc.candidates)
			if err != nil {
				t.Fatal(err)
			}
			for attempt := 0; attempt < 2; attempt++ {
				state, err := index.Resolve(wanted, tc.descriptor)
				if err != nil || state != tc.want {
					t.Fatalf("got %#x %v; want %#x", state, err, tc.want)
				}
			}
			// A previous relaxed query must not change a later exact lookup.
			state, err := index.Resolve(old.Identity, CBSParentVersionComparison{"EQ", "EQ", "EQ", false})
			var expected uint32
			for _, c := range tc.candidates {
				if c.Identity.ExactKey() == old.Identity.ExactKey() {
					expected = c.IntendedState
				}
			}
			if err != nil || state != expected {
				t.Fatalf("mutated index: %#x %v", state, err)
			}
		})
	}
}

func TestCBSParentVersionIdentityIsolationAndErrors(t *testing.T) {
	wanted := parentVersionIdentity("10.0.26100.1742")
	for _, change := range []func(*AssemblyIdentity){
		func(id *AssemblyIdentity) { id.Name += "-Other" },
		func(id *AssemblyIdentity) { id.ProcessorArchitecture = "x86" },
		func(id *AssemblyIdentity) { id.PublicKeyToken = "b03f5f7f11d50a3a" },
		func(id *AssemblyIdentity) { id.Language = "en-US" },
	} {
		other := wanted
		change(&other)
		index, err := NewCBSParentStateIndex([]CBSParentCandidate{{Identity: other, IntendedState: 0x70}})
		if err != nil {
			t.Fatal(err)
		}
		if state, err := index.Resolve(wanted, CBSParentVersionComparison{"EQ", "GE", "GE", true}); state != 0 || err != nil {
			t.Fatalf("cross-family match: %#x %v", state, err)
		}
	}
	for _, candidates := range [][]CBSParentCandidate{
		{{Identity: wanted, IntendedState: 0x60}},
		{{Identity: wanted, IntendedState: 0x40}, {Identity: wanted, IntendedState: 0x70}},
		{{Identity: parentVersionIdentity("10.0.65536.1"), IntendedState: 0x70}},
	} {
		if index, err := NewCBSParentStateIndex(candidates); err == nil || index != nil {
			t.Fatalf("accepted invalid snapshot: %v %v", index, err)
		}
	}
	index, err := NewCBSParentStateIndex(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := index.Resolve(wanted, CBSParentVersionComparison{}); err == nil {
		t.Fatal("guessed missing descriptor policy")
	}
	if _, err := index.Resolve(wanted, CBSParentVersionComparison{"EQ", "unknown", "GE", false}); err == nil {
		t.Fatal("accepted unknown operator")
	}
}
