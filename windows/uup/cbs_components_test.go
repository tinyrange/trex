package uup

import (
	"fmt"
	"strings"
	"testing"
)

func componentTestIdentity(version string) AssemblyIdentity {
	return AssemblyIdentity{Name: "Feature.Component", Version: version, ProcessorArchitecture: "amd64", Language: "neutral", PublicKeyToken: "31bf3856ad364e35", VersionScope: "nonSxS"}
}
func componentTestEntry(t *testing.T, version string, owners ...uint32) CBSComponentInventoryEntry {
	t.Helper()
	b, err := marshalCSIIdentity(componentTestIdentity(version))
	if err != nil {
		t.Fatal(err)
	}
	return CBSComponentInventoryEntry{b, owners}
}

func TestCBSComponentSelfUpdateBranches(t *testing.T) {
	for _, tc := range []struct {
		name, target, elevation string
		entries                 []CBSComponentInventoryEntry
		want                    bool
	}{
		{"no active owner", "10.0.200.1", "build", []CBSComponentInventoryEntry{componentTestEntry(t, "10.0.100.1", 8)}, false},
		{"presence is not installation", "10.0.200.1", "build", []CBSComponentInventoryEntry{componentTestEntry(t, "10.0.100.1")}, false},
		{"build crosses build", "10.0.200.1", "build", []CBSComponentInventoryEntry{componentTestEntry(t, "10.0.100.1", 128)}, true},
		{"revision cannot cross build", "10.0.200.1", "revision", []CBSComponentInventoryEntry{componentTestEntry(t, "10.0.100.1", 128)}, false},
		{"distribution cannot cross build", "10.0.200.1", "distribution", []CBSComponentInventoryEntry{componentTestEntry(t, "10.0.100.1", 128)}, false},
		{"build cannot cross version", "11.0.100.1", "build", []CBSComponentInventoryEntry{componentTestEntry(t, "10.0.100.1", 128)}, false},
		{"version can cross version", "11.0.100.1", "version", []CBSComponentInventoryEntry{componentTestEntry(t, "10.0.100.1", 128)}, true},
		{"revision same branch", "10.0.100.2", "revision", []CBSComponentInventoryEntry{componentTestEntry(t, "10.0.100.1", 9)}, true},
		{"self not predecessor", "10.0.100.1", "build", []CBSComponentInventoryEntry{componentTestEntry(t, "10.0.100.1", 128)}, false},
		{"higher not predecessor", "10.0.100.1", "build", []CBSComponentInventoryEntry{componentTestEntry(t, "10.0.200.1", 128)}, false},
		{"install without predecessor", "10.0.100.1", "install", nil, true},
		// Latest lower non-active owners can advance one branch independently of
		// the active owner which supplied the original activation evidence.
		{"latest build branch", "10.0.200.2", "revision", []CBSComponentInventoryEntry{componentTestEntry(t, "10.0.200.1", 8), componentTestEntry(t, "10.0.100.1", 128)}, true},
		{"latest version branch", "11.0.200.2", "build", []CBSComponentInventoryEntry{componentTestEntry(t, "11.0.100.1", 32), componentTestEntry(t, "10.0.100.1", 128)}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			index, err := NewCBSComponentStateIndex(tc.entries)
			if err != nil {
				t.Fatal(err)
			}
			got, err := index.SelfUpdate(componentTestIdentity(tc.target), tc.elevation)
			if err != nil || got != tc.want {
				t.Fatalf("got %v err=%v want=%v", got, err, tc.want)
			}
		})
	}
}

func TestCBSComponentInventoryIsolationAndValidation(t *testing.T) {
	entry := componentTestEntry(t, "10.0.100.1", 128)
	index, err := NewCBSComponentStateIndex([]CBSComponentInventoryEntry{entry})
	if err != nil {
		t.Fatal(err)
	}
	entry.Owners[0] = 8
	entry.Identity[0] = 'X'
	target := componentTestIdentity("10.0.100.2")
	if got, err := index.SelfUpdate(target, "revision"); err != nil || !got {
		t.Fatal(got, err)
	}
	for _, mutate := range []func(*AssemblyIdentity){
		func(id *AssemblyIdentity) { id.ProcessorArchitecture = "x86" },
		func(id *AssemblyIdentity) { id.VersionScope = "" },
		func(id *AssemblyIdentity) { id.Language = "en-US" },
		func(id *AssemblyIdentity) { id.Attributes = []ManifestAttribute{{Name: "type", Value: "win32"}} },
	} {
		id := target
		mutate(&id)
		if got, err := index.SelfUpdate(id, "revision"); err != nil || got {
			t.Fatal("foreign family matched", id, got, err)
		}
	}
	for _, entries := range [][]CBSComponentInventoryEntry{
		{componentTestEntry(t, "10.0.100.1", 0)},
		{componentTestEntry(t, "10.0.100.1", 16)},
		{componentTestEntry(t, "10.0.100.1", 128), componentTestEntry(t, "10.0.100.1", 9)},
		{{Identity: []byte("bad identity")}},
	} {
		if result, err := NewCBSComponentStateIndex(entries); err == nil || result != nil {
			t.Fatal("accepted bad component inventory")
		}
	}
	if _, err := index.SelfUpdate(target, "unknown"); err == nil {
		t.Fatal("accepted elevation")
	}
	var missing *CBSComponentStateIndex
	if _, err := missing.SelfUpdate(target, "install"); err == nil {
		t.Fatal("missing snapshot treated as empty")
	}
}

func TestCBSUpdateComponentSnapshotAndPublishedTargets(t *testing.T) {
	ref := `<assemblyIdentity name="Feature.Component" version="10.0.200.1" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS"/>`
	m := cbsIntentManifest(t, "Wrapper", "neutral", `<update name="a"><applicable disposition="staged"><updateComponent elevate="build">`+ref+`</updateComponent></applicable></update><update name="b"><applicable disposition="detect"><detectUpdate><update name="a"/></detectUpdate></applicable></update>`)
	bare, err := NewCBSUpdateStateIndex([]CBSPackageIntent{{Manifest: m, IntendedState: 0x70}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bare.UpdateState(m.Identity, "b"); err == nil {
		t.Fatal("missing component snapshot accepted")
	}
	active, err := NewCBSComponentStateIndex([]CBSComponentInventoryEntry{componentTestEntry(t, "10.0.100.1", 128)})
	if err != nil {
		t.Fatal(err)
	}
	empty, err := NewCBSComponentStateIndex(nil)
	if err != nil {
		t.Fatal(err)
	}
	old, err := bare.WithComponentState(active)
	if err != nil {
		t.Fatal(err)
	}
	check := func(index *CBSUpdateStateIndex, update string, want uint32) {
		t.Helper()
		got, err := index.UpdateState(m.Identity, update)
		if err != nil || got.RawState != want {
			t.Fatal(got, err, want)
		}
	}
	check(old, "b", 0x70)
	next, err := old.WithComponentState(empty)
	if err != nil {
		t.Fatal(err)
	}
	check(next, "b", 0x40)
	check(old, "b", 0x70)
	pub, err := old.WithPublishedUpdates(m.Identity, map[string]uint32{"a": 0x70})
	if err != nil {
		t.Fatal(err)
	}
	pub, err = pub.WithComponentState(empty)
	if err != nil {
		t.Fatal(err)
	}
	check(pub, "b", 0x70)
	got, err := pub.ApplicableUpdateState(m.Identity, "a")
	if err != nil || got.RawState != 0x40 {
		t.Fatal(got, err)
	}
	// Package target replacements preserve the analyzer snapshot too.
	capped, err := old.WithIntendedStates([]CBSUpdateIntentChange{{m.Identity, 0x40}})
	if err != nil {
		t.Fatal(err)
	}
	got, err = capped.UpdateState(m.Identity, "a")
	if err != nil || got != (CBSUpdateState{0x70, 0x40}) {
		t.Fatal(got, err)
	}
	for _, tc := range []struct {
		inner, disposition string
		want               uint32
	}{
		{strings.ReplaceAll(ref, "Feature.Component", "Missing") + ref, "staged", 0x70},
		{strings.ReplaceAll(ref, "Feature.Component", "Missing"), "detect", 0},
	} {
		xml := fmt.Sprintf(`<update name="a"><applicable disposition="%s"><updateComponent elevate="build">%s</updateComponent></applicable></update>`, tc.disposition, tc.inner)
		manifest := cbsIntentManifest(t, "Other", "neutral", xml)
		index, err := NewCBSUpdateStateIndex([]CBSPackageIntent{{Manifest: manifest, IntendedState: 0x70}})
		if err != nil {
			t.Fatal(err)
		}
		index, err = index.WithComponentState(active)
		if err != nil {
			t.Fatal(err)
		}
		state, err := index.UpdateState(manifest.Identity, "a")
		if err != nil || state.RawState != tc.want {
			t.Fatal(state, err, tc.want)
		}
	}
}
