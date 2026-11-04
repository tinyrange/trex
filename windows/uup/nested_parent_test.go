package uup

import (
	"strings"
	"testing"
)

// Native MediaPlayer language-wrapper shape (26100.9457): the neutral feature
// AND either the client or server language pack, not three independent parents.
func TestNestedParentRequiresFeatureAndLanguage(t *testing.T) {
	m, err := ParseAssemblyManifest(strings.NewReader(`<assembly><assemblyIdentity name="wrapper"/><package>
 <parent revisionCompare="GE" integrate="standalone" disposition="detect">
 <parent revisionCompare="GE" integrate="standalone" disposition="detect">
 <assemblyIdentity name="Client-LanguagePack" version="10.0.26100.1742" processorArchitecture="amd64" publicKeyToken="token" language="en-US"/>
 <assemblyIdentity name="Server-LanguagePack" version="10.0.26100.1742" processorArchitecture="amd64" publicKeyToken="token" language="en-US"/>
 </parent>
 <assemblyIdentity name="MediaPlayer" version="10.0.26100.1742" processorArchitecture="amd64" publicKeyToken="token" language="neutral"/>
 </parent></package></assembly>`))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.PackageParents) != 2 || m.PackageParents[1].ParentGroup != 1 || m.References[0].ParentGroup != 2 || m.References[2].ParentGroup != 1 {
		t.Fatalf("lost nested structure: %#v %#v", m.PackageParents, m.References)
	}
	feature := "MediaPlayer~token~amd64~~10.0.26100.9457.mum"
	client := "Client-LanguagePack~token~amd64~en-US~10.0.26100.9457.mum"
	server := "Server-LanguagePack~token~amd64~en-US~10.0.26100.9457.mum"
	for _, tc := range []struct {
		name      string
		installed []string
		want      bool
	}{
		{"none", nil, false}, {"feature only", []string{feature}, false}, {"language only", []string{client}, false},
		{"client", []string{feature, client}, true}, {"server", []string{feature, server}, true},
		{"wrong language", []string{feature, strings.ReplaceAll(client, "en-US", "fr-FR")}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state, err := newAssemblyImageState(tc.installed, nil)
			if err != nil {
				t.Fatal(err)
			}
			if got := packageManifestApplicable(m, state, nil); got != tc.want {
				t.Fatalf("applicable=%v, want %v", got, tc.want)
			}
		})
	}
	state, err := newAssemblyImageState([]string{feature}, nil)
	if err != nil {
		t.Fatal(err)
	}
	selected := m.References[0].Identity
	selected.Version = "10.0.26100.9711"
	if !packageManifestApplicable(m, state, map[string]AssemblyIdentity{selected.ExactKey(): selected}) {
		t.Fatal("selected language package did not satisfy nested prerequisite")
	}
}

func TestParentTreeAlternativeReduction(t *testing.T) {
	m, err := ParseAssemblyManifest(strings.NewReader(`<assembly><assemblyIdentity name="wrapper"/><package>
 <parent><assemblyIdentity name="a"/><parent><assemblyIdentity name="b"/><parent><assemblyIdentity name="c"/></parent></parent><parent><assemblyIdentity name="d"/></parent></parent>
 <parent><assemblyIdentity name="e"/></parent>
 </package></assembly>`))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		names string
		want  bool
	}{{"a", false}, {"ab", false}, {"abc", true}, {"ad", true}, {"bcd", false}, {"e", true}} {
		if got := packageParentsMatch(m, func(r AssemblyReference) bool { return strings.Contains(tc.names, r.Identity.Name) }); got != tc.want {
			t.Fatalf("parents %q: %v, want %v", tc.names, got, tc.want)
		}
	}
	m.PackageParents[1].ParentGroup = 2
	if packageParentsMatch(m, func(AssemblyReference) bool { return true }) {
		t.Fatal("accepted cyclic parent tree")
	}
}
