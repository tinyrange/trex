package uup

import (
	"fmt"
	"strings"
	"testing"
)

func TestParentBuildComparisonPreservesEditionIdentity(t *testing.T) {
	state, err := newAssemblyImageState([]string{"Microsoft-Windows-ProfessionalEdition~token~amd64~~10.0.26100.9457.mum"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, version, arch, token, language, attrs string
		want                                        bool
	}{
		{"same build", "10.0.26100.1", "amd64", "token", "neutral", `buildCompare="EQ"`, true},
		{"implicit exact", "10.0.26100.1", "amd64", "token", "neutral", "", false},
		{"exact", "10.0.26100.9457", "amd64", "token", "neutral", "", true},
		{"other build", "10.0.26200.1", "amd64", "token", "neutral", `buildCompare="EQ"`, false},
		{"other architecture", "10.0.26100.1", "arm64", "token", "neutral", `buildCompare="EQ"`, false},
		{"other publisher", "10.0.26100.1", "amd64", "foreign", "neutral", `buildCompare="EQ"`, false},
		{"other language", "10.0.26100.1", "amd64", "token", "fr-FR", `buildCompare="EQ"`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			xml := fmt.Sprintf(`<assembly><assemblyIdentity name="package" version="1"/><package><parent %s><assemblyIdentity name="Microsoft-Windows-ProfessionalEdition" version="%s" processorArchitecture="%s" publicKeyToken="%s" language="%s"/></parent></package></assembly>`, tc.attrs, tc.version, tc.arch, tc.token, tc.language)
			manifest, err := ParseAssemblyManifest(strings.NewReader(xml))
			if err != nil {
				t.Fatal(err)
			}
			if got := packageManifestApplicable(manifest, state, nil); got != tc.want {
				t.Fatalf("applicable=%v want %v", got, tc.want)
			}
		})
	}
}

func TestServicingStackAggregatesDoNotDowngrade(t *testing.T) {
	state, err := newAssemblyImageState([]string{"Package_for_ServicingStack_9441~token~amd64~~26100.9441.1.11.mum"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		revision, version, arch string
		want                    bool
	}{
		{"1738", "26100.1738.1.0", "amd64", true}, {"9441", "26100.9441.1.11", "amd64", true}, {"9703", "26100.9703.1.4", "amd64", false}, {"1738", "26100.1738.1.0", "arm64", false},
	} {
		id := AssemblyIdentity{Name: "Package_for_ServicingStack_" + tc.revision, Version: tc.version, ProcessorArchitecture: tc.arch, PublicKeyToken: "token"}
		if got := state.hasSupersedingServicingStack(id); got != tc.want {
			t.Fatalf("%+v: %v", tc, got)
		}
	}
}

func TestUnsupportedParentComparisonRejected(t *testing.T) {
	for _, a := range []ManifestAttribute{{Name: "buildCompare", Value: "GT"}, {Name: "revisionCompare", Value: "NE"}} {
		m := &AssemblyManifest{References: []AssemblyReference{{Kind: "parent", Attributes: []ManifestAttribute{a}}}}
		if err := validateParentComparisons(m); err == nil {
			t.Fatalf("accepted unsupported %v", a)
		}
	}
	m := &AssemblyManifest{References: []AssemblyReference{{Kind: "parent", Attributes: []ManifestAttribute{{Name: "buildCompare", Value: "EQ"}}}}}
	if err := validateParentComparisons(m); err != nil {
		t.Fatal(err)
	}
}

func TestCheckpointParentRevisionComparisons(t *testing.T) {
	// The 26100.9711 VirtualMachinePlatform wrapper requires revision >=1742.
	// ISO 26100.9457 has the same wrapper predicate and the newer installed parent.
	wanted := AssemblyIdentity{Name: "HyperV-OptionalFeature-VirtualMachinePlatform-Client-Disabled-FOD-Package", Version: "10.0.26100.1742", ProcessorArchitecture: "amd64", PublicKeyToken: "31bf3856ad364e35"}
	for _, tc := range []struct {
		version, build, revision string
		want                     bool
	}{
		{"10.0.26100.1741", "", "GE", false},
		{"10.0.26100.1742", "", "GE", true},
		{"10.0.26100.9457", "", "GE", true},
		{"10.0.26200.9457", "", "GE", false},
		{"10.1.26100.9457", "", "GE", false},
		{"10.0.26100.9457", "EQ", "EQ", false},
		{"10.0.26100.1742", "EQ", "EQ", true},
		{"10.0.26100.1", "EQ", "", true},
		{"10.0.26099.9457", "GE", "GE", false},
		{"10.0.26200.9457", "GE", "GE", true},
		// CBS stops at a successful unequal build comparison. Requiring the
		// revision comparison too incorrectly rejects newer build baselines.
		{"10.0.26200.1", "GE", "GE", true},
		{"10.0.26200.1", "GE", "EQ", true},
		{"10.0.26100.1", "GE", "GE", false},
		{"10.0.26100.1", "GE", "EQ", false},
		{"10.0.26099.9999", "GE", "GE", false},
	} {
		ref := AssemblyReference{Kind: "parent", Identity: wanted, Attributes: []ManifestAttribute{{Name: "buildCompare", Value: tc.build}, {Name: "revisionCompare", Value: tc.revision}}}
		actual := wanted
		actual.Version = tc.version
		if got := parentIdentityMatches(ref, actual); got != tc.want {
			t.Fatalf("%+v: %v", tc, got)
		}
		actual.ProcessorArchitecture = "arm64"
		if parentIdentityMatches(ref, actual) {
			t.Fatal("comparison ignored architecture")
		}
	}
}

func TestCheckpointAggregateCannotDowngrade(t *testing.T) {
	state, err := newAssemblyImageState([]string{"Package_for_RollupFix~token~amd64~~26100.9457.1.7.mum"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		version string
		want    bool
	}{{"26100.1742.1.10", true}, {"26100.9457.1.7", true}, {"26100.9711.1.12", false}} {
		id := AssemblyIdentity{Name: "Package_for_RollupFix", PublicKeyToken: "token", ProcessorArchitecture: "amd64", Version: tc.version}
		if got := state.hasSupersedingAggregate(id); got != tc.want {
			t.Fatalf("%s: %v", tc.version, got)
		}
		id.PublicKeyToken = "other"
		if state.hasSupersedingAggregate(id) {
			t.Fatal("ignored publisher")
		}
	}
}

func TestParentFamilyIndexKeepsHistoricalBuildsAndNewStages(t *testing.T) {
	state, err := newAssemblyImageState([]string{
		"Parent~token~amd64~~10.0.26100.10.mum",
		"PARENT~token~amd64~~10.0.26200.20.mum",
		"Parent~token~arm64~~10.0.26100.100.mum",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	identity := AssemblyIdentity{Name: "parent", PublicKeyToken: "token", ProcessorArchitecture: "amd64", Version: "10.0.26100.1"}
	ref := AssemblyReference{Identity: identity, Attributes: []ManifestAttribute{{Name: "buildCompare", Value: "EQ"}, {Name: "revisionCompare", Value: "GE"}}}
	if !state.hasInstalledParent(ref) {
		t.Fatal("lost older build behind latest family version")
	}
	ref.Identity.Version = "10.0.26100.50"
	if state.hasInstalledParent(ref) {
		t.Fatal("used another architecture's revision")
	}
	next := identity
	next.Version = "10.0.26100.60"
	state.rememberPackage(next)
	state.rememberPackage(next)
	if !state.hasInstalledParent(ref) {
		t.Fatal("new stage missing from parent index")
	}
	if len(state.packagesByStable[identity.StableKey()]) != 3 {
		t.Fatal("duplicate or lost version in family index")
	}
}
