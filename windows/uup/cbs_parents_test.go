package uup

import (
	"errors"
	"strings"
	"testing"
)

func parentStateManifest(t *testing.T, parents string) *AssemblyManifest {
	t.Helper()
	m, err := ParseAssemblyManifest(strings.NewReader(`<assembly xmlns="urn:schemas-microsoft-com:asm.v3"><assemblyIdentity name="wrapper"/><package>` + parents + `</package></assembly>`))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// Native 3ad70 substitutes disposition only below installed. In particular,
// missing/detect is absent, not staged; superseded/detect remains superseded.
func TestCBSParentDispositionBoundaries(t *testing.T) {
	states := []uint32{0, 0x20, 0x40, 0x50, 0x70, 0x80}
	for _, tc := range []struct {
		attr string
		want []uint32
	}{
		{"", []uint32{0, 0x20, 0x40, 0x50, 0x70, 0x70}},
		{`disposition="detect"`, []uint32{0, 0x20, 0x40, 0x50, 0x70, 0x70}},
		{`disposition="staged"`, []uint32{0x40, 0x40, 0x40, 0x40, 0x70, 0x70}},
		{`disposition="absent"`, []uint32{0, 0, 0, 0, 0x70, 0x70}},
	} {
		m := parentStateManifest(t, `<parent `+tc.attr+`><assemblyIdentity name="feature"/></parent>`)
		for i, state := range states {
			got, err := EvaluateCBSPackageParents(m, CBSParentEvaluation{Resolve: func(AssemblyReference) (uint32, error) { return state, nil }})
			if err != nil || got != tc.want[i] {
				t.Fatalf("%s state=%#x: got %#x, %v; want %#x", tc.attr, state, got, err, tc.want[i])
			}
		}
	}
	m := parentStateManifest(t, `<parent set="languageResources" distributionCompare="EQ" serviceCompare="EQ"><assemblyIdentity name="feature"/></parent>`)
	if got, err := EvaluateCBSPackageParents(m, CBSParentEvaluation{Resolve: func(AssemblyReference) (uint32, error) { return 0x40, nil }}); err != nil || got != 0x40 {
		t.Fatalf("named parent set changed state: %#x %v", got, err)
	}
	m = parentStateManifest(t, "")
	if got, err := EvaluateCBSPackageParents(m, CBSParentEvaluation{}); err != nil || got != CBSStateUnspecified {
		t.Fatalf("no parents: %#x %v", got, err)
	}
}

// Counterexamples to flattening all parent identities into one OR, to taking
// minimum across direct alternatives, and to treating root blocks conjunctively.
func TestCBSParentStateTree(t *testing.T) {
	m := parentStateManifest(t, `<parent>
 <assemblyIdentity name="feature"/><assemblyIdentity name="feature-alt"/>
 <parent><assemblyIdentity name="client-language"/></parent>
 <parent><assemblyIdentity name="server-language"/></parent>
 </parent><parent><assemblyIdentity name="root-alt"/></parent>`)
	for _, tc := range []struct {
		name   string
		states map[string]uint32
		want   uint32
	}{
		{"absent", nil, 0},
		{"feature only", map[string]uint32{"feature": 0x70}, 0},
		{"language only", map[string]uint32{"client-language": 0x70}, 0},
		{"staged feature", map[string]uint32{"feature": 0x40, "client-language": 0x70}, 0x40},
		{"staged language", map[string]uint32{"feature": 0x70, "client-language": 0x40}, 0x40},
		{"direct alternative", map[string]uint32{"feature": 0x40, "feature-alt": 0x70, "client-language": 0x70}, 0x70},
		{"nested alternative", map[string]uint32{"feature": 0x70, "client-language": 0x40, "server-language": 0x70}, 0x70},
		{"root alternative", map[string]uint32{"root-alt": 0x70}, 0x70},
		{"superseded not staged", map[string]uint32{"feature": 0x70, "server-language": 0x50}, 0x50},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := EvaluateCBSPackageParents(m, CBSParentEvaluation{Resolve: func(r AssemblyReference) (uint32, error) {
				return tc.states[r.Identity.Name], nil
			}})
			if err != nil || got != tc.want {
				t.Fatalf("got %#x, %v; want %#x", got, err, tc.want)
			}
		})
	}
}

func TestCBSParentStandaloneRequiresExplicitPolicy(t *testing.T) {
	// Parent integration has a separate enum from package-reference owners:
	// separate=2 (default), delegate=3, subsume=4, not visible/hidden/liberate.
	for _, integration := range []string{"", "separate", "delegate", "subsume"} {
		attr := ""
		if integration != "" {
			attr = ` integrate="` + integration + `"`
		}
		m := parentStateManifest(t, `<parent`+attr+`><assemblyIdentity name="missing"/></parent>`)
		got, err := EvaluateCBSPackageParents(m, CBSParentEvaluation{StandaloneSatisfied: true,
			Resolve: func(AssemblyReference) (uint32, error) { return 0, nil },
		})
		if got != 0 || err != nil {
			t.Fatalf("non-standalone %q bypassed: %#x %v", integration, got, err)
		}
	}
	m := parentStateManifest(t, `<parent integrate="standalone"><assemblyIdentity name="missing"/>
 <parent><assemblyIdentity name="language"/></parent></parent>`)
	for _, tc := range []struct {
		bypass         bool
		language, want uint32
	}{
		{false, 0x70, 0}, {true, 0x70, 0x70}, {true, 0x40, 0x40}, {true, 0, 0},
	} {
		got, err := EvaluateCBSPackageParents(m, CBSParentEvaluation{
			StandaloneSatisfied: tc.bypass,
			Resolve: func(r AssemblyReference) (uint32, error) {
				if r.Identity.Name == "missing" {
					if tc.bypass {
						t.Fatal("standalone bypass queried direct identity")
					}
					return 0, nil
				}
				return tc.language, nil
			},
		})
		if err != nil || got != tc.want {
			t.Fatalf("%+v: %#x %v", tc, got, err)
		}
	}
}

func TestCBSParentEvaluationFailuresAndShortCircuit(t *testing.T) {
	for _, parents := range []string{
		`<parent/>`,
		`<parent><parent><assemblyIdentity name="nested"/></parent></parent>`,
		`<parent disposition="unknown"><assemblyIdentity name="a"/></parent>`,
		`<parent mystery="true"><assemblyIdentity name="a"/></parent>`,
		`<parent integrate="unknown"><assemblyIdentity name="a"/></parent>`,
		`<parent set=""><assemblyIdentity name="a"/></parent>`,
	} {
		m := parentStateManifest(t, parents)
		if got, err := EvaluateCBSPackageParents(m, CBSParentEvaluation{Resolve: func(AssemblyReference) (uint32, error) {
			t.Fatal("invalid tree reached resolver")
			return 0x70, nil
		}}); err == nil || got != 0 {
			t.Fatalf("accepted %s: %#x %v", parents, got, err)
		}
	}
	m := parentStateManifest(t, `<parent><assemblyIdentity name="a"/></parent>`)
	if _, err := EvaluateCBSPackageParents(m, CBSParentEvaluation{}); err == nil {
		t.Fatal("accepted missing resolver")
	}
	for _, state := range []uint32{5, 0x60, CBSStateUnspecified, 0xffffffc0} {
		if got, err := EvaluateCBSPackageParents(m, CBSParentEvaluation{Resolve: func(AssemblyReference) (uint32, error) {
			return state, nil
		}}); err == nil || got != 0 {
			t.Fatalf("accepted unresolved state %#x: %#x %v", state, got, err)
		}
	}
	problem := errors.New("parent query failed")
	if got, err := EvaluateCBSPackageParents(m, CBSParentEvaluation{Resolve: func(AssemblyReference) (uint32, error) {
		return 0, problem
	}}); got != 0 || !errors.Is(err, problem) {
		t.Fatalf("lost query error: %#x %v", got, err)
	}
	m.PackageParents[0].ParentGroup = 1
	if _, err := EvaluateCBSPackageParents(m, CBSParentEvaluation{}); err == nil {
		t.Fatal("accepted self cycle")
	}
	m.PackageParents[0].ParentGroup = 0
	m.References[0].ParentGroup = 2
	if _, err := EvaluateCBSPackageParents(m, CBSParentEvaluation{}); err == nil {
		t.Fatal("accepted invalid reference group")
	}
	m = parentStateManifest(t, `<parent><assemblyIdentity name="a"/>
 <parent><assemblyIdentity name="unreachable"/></parent></parent>`)
	if got, err := EvaluateCBSPackageParents(m, CBSParentEvaluation{Resolve: func(r AssemblyReference) (uint32, error) {
		if r.Identity.Name == "unreachable" {
			return 0, problem
		}
		return 0, nil
	}}); got != 0 || err != nil {
		t.Fatalf("absent direct state did not short circuit: %#x %v", got, err)
	}
}
