package uup

import (
	"fmt"
	"strings"
	"testing"
)

func scopeRef(name, version string) string {
	return fmt.Sprintf(`<assemblyIdentity name="%s" version="%s" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral"/>`, name, version)
}

func TestCBSParentUpdateScope(t *testing.T) {
	name := parentVersionIdentity("10.0.26100.1742").Name
	ref := func(version string) string { return scopeRef(name, version) }
	exact := CBSParentVersionComparison{"EQ", "EQ", "EQ", true}
	floor := CBSParentVersionComparison{"EQ", "EQ", "GE", false}
	candidates := []CBSParentCandidate{
		{Identity: parentVersionIdentity("10.0.26100.1"), IntendedState: 0x70},
		{Identity: parentVersionIdentity("10.0.26100.1742"), IntendedState: 0x40, Baseline: true},
		{Identity: parentVersionIdentity("10.0.26100.9457"), IntendedState: 0},
	}
	other := parentVersionIdentity("10.0.26100.1")
	other.Name = "Other-Package"
	candidates = append(candidates, CBSParentCandidate{Identity: other, IntendedState: 0x70})
	index, err := NewCBSParentStateIndex(candidates)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, xml   string
		descriptors []CBSParentVersionComparison
		versions    string
	}{
		{"exact ignores nested failure", "<parent>" + ref("10.0.26100.1742") + "<parent>" + scopeRef("Missing-Package", "10.0.26100.1") + "</parent></parent>", []CBSParentVersionComparison{exact, exact}, "10.0.26100.1742"},
		{"missing exact not substituted", "<parent>" + ref("10.0.26100.2") + "</parent>", []CBSParentVersionComparison{exact}, ""},
		{"range no state filter or baseline relaxation", "<parent>" + ref("10.0.26100.1742") + "</parent>", []CBSParentVersionComparison{floor}, "10.0.26100.1742,10.0.26100.9457"},
		{"nested alternative same family accepts old", "<parent>" + ref("10.0.26100.1742") + "<parent>" + ref("10.0.26100.1") + "</parent></parent>", []CBSParentVersionComparison{floor, {"EQ", "EQ", "EQ", false}}, "10.0.26100.1,10.0.26100.1742,10.0.26100.9457"},
		{"nested foreign family does not seed", "<parent>" + ref("10.0.26100.1742") + "<parent>" + scopeRef(other.Name, other.Version) + "</parent></parent>", []CBSParentVersionComparison{floor, exact}, "10.0.26100.1742,10.0.26100.9457"},
		{"nested rule not queried for exact root", "<parent>" + ref("10.0.26100.1742") + "<parent>" + ref("10.0.26100.1") + "</parent></parent>", []CBSParentVersionComparison{exact, floor}, "10.0.26100.1742"},
		{"deduplicate root selections", "<parent>" + ref("10.0.26100.1742") + "</parent><parent>" + ref("10.0.26100.1742") + "</parent>", []CBSParentVersionComparison{floor, {"EQ", "EQ", "EQ", false}}, "10.0.26100.1742,10.0.26100.9457"},
		{"exact rule inside ranged query honors ignore", "<parent>" + ref("10.0.26100.1742") + "</parent><parent>" + ref("10.0.26100.1742") + "</parent>", []CBSParentVersionComparison{floor, exact}, "10.0.26100.1,10.0.26100.1742,10.0.26100.9457"},
		{"no parents", "", nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := index.ParentUpdateScope(parentStateManifest(t, tc.xml), tc.descriptors)
			var versions []string
			for _, id := range got {
				versions = append(versions, id.Version)
			}
			if err != nil || strings.Join(versions, ",") != tc.versions {
				t.Fatalf("scope=%v err=%v want=%s", versions, err, tc.versions)
			}
		})
	}
	// Parent-state lookup intentionally differs: matching staged Baseline relaxes
	// subsequent revision comparisons and permits the installed older package.
	state, err := index.Resolve(candidates[1].Identity, floor)
	if err != nil || state != 0x70 {
		t.Fatalf("state=%#x err=%v", state, err)
	}
}

func TestCBSParentUpdateScopeErrors(t *testing.T) {
	index, err := NewCBSParentStateIndex(nil)
	if err != nil {
		t.Fatal(err)
	}
	valid := "<parent>" + scopeRef("Feature-Package", "10.0.26100.1") + "</parent>"
	exact := []CBSParentVersionComparison{{"EQ", "EQ", "EQ", false}}
	for _, tc := range []struct {
		xml         string
		descriptors []CBSParentVersionComparison
		mutate      func(*AssemblyManifest)
	}{
		{valid, nil, nil},
		{valid, []CBSParentVersionComparison{{}}, nil},
		{"<parent/>", exact, nil},
		{"<parent>" + scopeRef("Feature-Package", "10.0.65536.1") + "</parent>", exact, nil},
		{valid, exact, func(m *AssemblyManifest) { m.PackageParents[0].ParentGroup = 1 }},
		{valid, exact, func(m *AssemblyManifest) { m.References[0].ParentGroup = 2 }},
	} {
		m := parentStateManifest(t, tc.xml)
		if tc.mutate != nil {
			tc.mutate(m)
		}
		if got, err := index.ParentUpdateScope(m, tc.descriptors); err == nil || got != nil {
			t.Fatalf("accepted malformed scope: %v %v", got, err)
		}
	}
}
