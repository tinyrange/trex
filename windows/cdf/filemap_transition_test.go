package cdf

import (
	"reflect"
	"strings"
	"testing"
)

func transitionOwner(name, version string) []IdentityAttribute {
	return []IdentityAttribute{{Name: "Name", Value: name}, {Name: "Version", Value: version},
		{Name: "PublicKeyToken", Value: "31bf3856ad364e35"}, {Name: "ProcessorArchitecture", Value: "amd64"}, {Name: "VersionScope", Value: "NonSxS"}}
}

func TestFileMapTransitionNativeGoldens(t *testing.T) {
	timezone := transitionOwner("Microsoft-Windows-Auto-Time-Zone-Updater-Service", "10.0.26100.9711")
	featureOld := transitionOwner("Microsoft-OneCore-Data-UsageAndQualityInsights", "10.0.26100.9278")
	featureNew := transitionOwner("Microsoft-OneCore-Data-UsageAndQualityInsights", "10.0.26100.9549")
	for _, tc := range []struct {
		name, before, want string
		nodes              []FileMapNode
	}{
		{"replacement", nativeTimeZoneBefore, nativeTimeZoneReplacement, []FileMapNode{{Name: "tzautoupdate.dat", Operation: 3, State: 2, AfterIdentity: timezone}}},
		{"removal", nativeTimeZoneBefore, nativeTimeZoneRemoval, []FileMapNode{{Name: "tzautoupdate.dat", Operation: 2, State: 0}}},
		{"addition", nativeFeatureConfigBefore, nativeFeatureConfigAddition, []FileMapNode{{Name: "ShellHealth_V10.json", Operation: 1, State: 2, AfterIdentity: featureNew}}},
		{"directory-owner", nativeFeatureConfigBefore, nativeFeatureConfigDirectoryReplacement, []FileMapNode{{Name: ".", Operation: 3, State: 4, BeforeIdentity: featureOld, AfterIdentity: featureNew}}},
		{"creation", "", nativeMathCATNewMap, []FileMapNode{{Name: "definitions.yaml", Operation: 1, State: 2, AfterIdentity: transitionOwner("Microsoft-Windows-Accessibility-MathCAT-Rules-de", "10.0.26100.9549")}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := readNativeFileMap(t, tc.want)
			input := &FileMap{Path: want.Path, RootSelector: want.RootSelector}
			if tc.before != "" {
				input = readNativeFileMap(t, tc.before)
			}
			initial := resolvedEntries(input)
			result, err := TransitionFileMap(input, tc.nodes)
			if err != nil {
				t.Fatal(err)
			}
			got := result.Document
			if len(result.DirectoryCollisions) != 0 {
				t.Fatal("unexpected native collision")
			}
			if !reflect.DeepEqual(initial, resolvedEntries(input)) {
				t.Fatal("input changed")
			}
			encoded, err := got.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			doc, err := Parse(encoded)
			if err != nil {
				t.Fatal(err)
			}
			roundtrip, err := doc.FileMap()
			if err != nil {
				t.Fatal(err)
			}
			if got.Path != want.Path || got.RootSelector != want.RootSelector || !reflect.DeepEqual(resolvedEntries(roundtrip), resolvedEntries(want)) || len(roundtrip.Identities) != len(want.Identities) {
				t.Fatal("transition disagrees with independently captured native output")
			}
		})
	}
}

func TestFileMapTransitionOwnershipBoundaries(t *testing.T) {
	input := readNativeFileMap(t, nativeTimeZoneBefore)
	other := transitionOwner("Different-Component", "10.0.26100.9711")
	n := FileMapNode{Name: "tzautoupdate.dat", Operation: 3, State: 2, AfterIdentity: other}
	if _, err := TransitionFileMap(input, []FileMapNode{n}); err == nil {
		t.Fatal("foreign owner admitted without native old-side flag")
	}
	n.DirectoryFlags = 8
	got, err := TransitionFileMap(input, []FileMapNode{n})
	if err != nil || resolvedEntries(got.Document)[n.Name].Owner[0].Value != "Different-Component" {
		t.Fatalf("old contribution did not admit transition: %v", err)
	}
	// The dot is compared to the old family. An unrelated old declaration
	// does not remove it, even when operation=2. With a new owner this is an
	// unresolved directory-owner collision, not blind overwrite permission.
	dot := FileMapNode{Name: ".", Operation: 2, State: 0, BeforeIdentity: other}
	got, err = TransitionFileMap(input, []FileMapNode{dot})
	if err != nil || !reflect.DeepEqual(resolvedEntries(got.Document), resolvedEntries(input)) {
		t.Fatalf("foreign dot owner removed: %v", err)
	}
	dot.Operation = 3
	dot.State = 4
	dot.AfterIdentity = other
	retained, err := TransitionFileMap(input, []FileMapNode{dot})
	if err != nil {
		t.Fatal(err)
	}
	if len(retained.DirectoryCollisions) != 1 || !reflect.DeepEqual(resolvedEntries(retained.Document), resolvedEntries(input)) {
		t.Fatal("native dot collision must retain existing ownership and report it")
	}
	diagnostic := retained.DirectoryCollisions[0]
	if !reflect.DeepEqual(diagnostic.RequestedIdentity, other) {
		t.Fatal("missing requested owner")
	}
	diagnostic.RetainedIdentity[0].Value = "changed diagnostic"
	if reflect.DeepEqual(diagnostic.RetainedIdentity, resolvedEntries(retained.Document)["."].Owner) {
		t.Fatal("diagnostic aliases document")
	}
	// Native family comparison excludes version and folds ASCII names, but
	// must not collapse architectures or token/culture/type/scope changes.
	a := transitionOwner("Component", "10.0.26100.1")
	b := transitionOwner("COMPONENT", "10.0.26100.9711")
	af, _ := fileMapFamily(a)
	bf, _ := fileMapFamily(b)
	if !sameFileMapFamily(af, bf) {
		t.Fatal("version/name-case control")
	}
	for _, key := range []string{"ProcessorArchitecture", "PublicKeyToken", "VersionScope"} {
		c := append([]IdentityAttribute(nil), b...)
		for i := range c {
			if c[i].Name == key {
				c[i].Value = "different"
			}
		}
		cf, err := fileMapFamily(c)
		if err != nil || sameFileMapFamily(af, cf) {
			t.Fatalf("family lost %s", key)
		}
	}
}

func TestFileMapTransitionPostPassStatesAndIsolation(t *testing.T) {
	owner := transitionOwner("Component", "10.0.26100.1")
	input := &FileMap{Path: "System32", RootSelector: 1}
	nodes := []FileMapNode{}
	for i, state := range []uint8{1, 2, 5, 6, 7} {
		nodes = append(nodes, FileMapNode{Name: string(rune('a' + i)), Operation: 1, State: state, AfterIdentity: owner, DirectoryFlags: 0x10, FileFlags: 2})
	}
	nodes = append(nodes, FileMapNode{Name: "excluded", Operation: 1, State: 2, AfterIdentity: owner, FileFlags: 0x40})
	got, err := TransitionFileMap(input, nodes)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Document.Entries) != 3 || len(got.Document.Identities) != 1 {
		t.Fatal("state gates or exact identity interning")
	}
	for _, e := range got.Document.Entries {
		if e.Flags != 6 {
			t.Fatal("native record flags not retained")
		}
	}
	got.Document.Identities[0][0].Value = "mutated"
	if owner[0].Value != "Component" || len(input.Entries) != 0 {
		t.Fatal("output aliases input")
	}
	existing := &FileMap{RootSelector: 1, Identities: [][]IdentityAttribute{owner}, Entries: []FileMapEntry{{Name: "writable", DisplayName: "writable", Identity: 0}}}
	empty, err := TransitionFileMap(existing, []FileMapNode{{Name: "writable", Operation: 3, State: 1, AfterIdentity: owner}})
	if err != nil || len(empty.Document.Entries) != 0 || len(empty.Document.Identities) != 0 {
		t.Fatalf("writable record was added: %v", err)
	}
	if _, err := empty.Document.Marshal(); err == nil {
		t.Fatal("empty result implicitly serialized")
	}
	duplicate := nodes[1]
	duplicate.Name = strings.ToUpper(duplicate.Name)
	if _, err := TransitionFileMap(input, append(nodes, duplicate)); err == nil {
		t.Fatal("case-insensitive duplicate accepted")
	}
	bad := *existing
	bad.Entries = append([]FileMapEntry(nil), existing.Entries...)
	bad.Entries[0].Identity = 99
	if _, err := TransitionFileMap(&bad, nil); err == nil {
		t.Fatal("invalid input reference accepted")
	}
	badOwner := append([]IdentityAttribute(nil), owner...)
	badOwner[0].Namespace = "unknown"
	if _, err := TransitionFileMap(input, []FileMapNode{{Name: "new", Operation: 1, State: 2, AfterIdentity: badOwner}}); err == nil {
		t.Fatal("unknown identity namespace ignored")
	}
}
