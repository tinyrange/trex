package uup

import "testing"

func TestCBSComponentSideBySideVersionIsolation(t *testing.T) {
	for _, scope := range []string{"", "sxs", "nonSxS", "NONSXS"} {
		t.Run(scope, func(t *testing.T) {
			entry := func(version string, owners ...uint32) CBSComponentInventoryEntry {
				id := componentTestIdentity(version)
				id.VersionScope = scope
				data, err := marshalCSIIdentity(id)
				if err != nil {
					t.Fatal(err)
				}
				return CBSComponentInventoryEntry{Identity: data, Owners: owners}
			}
			// The old major/minor is active; the new major/minor has only a
			// nonactivating version-elevation owner. Combining the families
			// incorrectly lends the old activation to the new build branch.
			index, err := NewCBSComponentStateIndex([]CBSComponentInventoryEntry{
				entry("5.82.100.1", 128), entry("6.0.100.1", 32),
			})
			if err != nil {
				t.Fatal(err)
			}
			target := componentTestIdentity("6.0.200.1")
			target.VersionScope = scope
			want := scope == "nonSxS" || scope == "NONSXS"
			for _, elevation := range []string{"build", "version"} {
				got, err := index.SelfUpdate(target, elevation)
				if err != nil || got != want {
					t.Fatalf("%s: got %v, %v; want %v", elevation, got, err, want)
				}
			}
			// A real active predecessor in the same major/minor still works.
			active, err := NewCBSComponentStateIndex([]CBSComponentInventoryEntry{entry("6.0.100.1", 128)})
			if err != nil {
				t.Fatal(err)
			}
			got, err := active.SelfUpdate(target, "build")
			if err != nil || !got {
				t.Fatal(got, err)
			}
		})
	}
}
