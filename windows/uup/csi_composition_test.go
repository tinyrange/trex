package uup

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func compositionFixture(t *testing.T, name, body string) *AssemblyManifest {
	t.Helper()
	m, err := ParseAssemblyManifest(strings.NewReader(`<assembly xmlns="urn:schemas-microsoft-com:asm.v3"><assemblyIdentity name="` + name + `" version="10.0.26100.1" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS"/>` + body + `</assembly>`))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func compositionEdge(name, kind string) string {
	return `<dependency><dependentAssembly dependencyType="` + kind + `"><assemblyIdentity name="` + name + `" version="10.0.26100.1" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS"/></dependentAssembly></dependency>`
}

func TestCSICompositionNativeImpactAndEdgeKinds(t *testing.T) {
	// WCP 26100.9441: type defaults to prerequisite (0), install is 1;
	// Drain follows only 1. Root impact is overridden by its initial disposition.
	// A diamond must revisit the shared member and its descendants in FIFO order.
	for _, reverse := range []bool{false, true} {
		t.Run(fmt.Sprint(reverse), func(t *testing.T) {
			edges := compositionEdge("Patch", "install") + compositionEdge("Install", "INSTALL")
			wantShared := uint32(2)
			if reverse {
				edges = compositionEdge("Install", "install") + compositionEdge("Patch", "install")
				wantShared = 1
			}
			manifests := map[string]*AssemblyManifest{
				"Root":     compositionFixture(t, "Root", `<deployment impact="patch"/>`+edges+compositionEdge("NotAnOwner", "")+compositionEdge("MissingPrerequisite", "prerequisite")),
				"Patch":    compositionFixture(t, "Patch", `<deployment impact="patch"/>`+compositionEdge("Shared", "install")),
				"Install":  compositionFixture(t, "Install", compositionEdge("Shared", "install")),
				"Shared":   compositionFixture(t, "Shared", compositionEdge("Leaf", "install")+compositionEdge("Override", "install")),
				"Leaf":     compositionFixture(t, "Leaf", ""),
				"Override": compositionFixture(t, "Override", `<deployment impact="install"/>`),
			}
			calls := map[string]int{}
			members, err := CalculateCSIComposition(manifests["Root"].Identity, func(id AssemblyIdentity) (*AssemblyManifest, error) {
				calls[id.Name]++
				m := manifests[id.Name]
				if m == nil {
					return nil, fmt.Errorf("unexpected resolution of %s", id.Name)
				}
				return m, nil
			}, 0)
			if err != nil {
				t.Fatal(err)
			}
			want := map[string]uint32{"Root": 2, "Patch": 1, "Install": 2, "Shared": wantShared, "Leaf": wantShared, "Override": 2}
			if len(members) != len(want) {
				t.Fatalf("members: %+v", members)
			}
			for _, member := range members {
				if member.Disposition != want[member.Identity.Name] {
					t.Errorf("%s disposition %d, want %d", member.Identity.Name, member.Disposition, want[member.Identity.Name])
				}
				if calls[member.Identity.Name] != 1 {
					t.Errorf("manifest was not cached: %v", calls)
				}
			}
		})
	}
}

func TestCSICompositionRejectsIncompleteOrForeignGraph(t *testing.T) {
	root := compositionFixture(t, "Root", compositionEdge("Child", "install"))
	child := compositionFixture(t, "Child", "")
	for _, tc := range []struct {
		name   string
		mutate func(*AssemblyManifest)
	}{
		{"version", func(m *AssemblyManifest) { m.Identity.Version = "10.0.26100.2" }},
		{"scope", func(m *AssemblyManifest) { m.Identity.VersionScope = "" }},
		{"type", func(m *AssemblyManifest) {
			m.Identity.Attributes = append(m.Identity.Attributes, ManifestAttribute{Name: "type", Value: "win32"})
		}},
		{"package", func(m *AssemblyManifest) { m.Package = &AssemblyPackage{} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wrong := *child
			wrong.Identity.Attributes = append([]ManifestAttribute(nil), child.Identity.Attributes...)
			tc.mutate(&wrong)
			got, err := CalculateCSIComposition(root.Identity, func(id AssemblyIdentity) (*AssemblyManifest, error) {
				if id.Name == "Root" {
					return root, nil
				}
				return &wrong, nil
			}, 0)
			if err == nil || got != nil {
				t.Fatalf("foreign graph accepted: %+v, %v", got, err)
			}
		})
	}
	missing := errors.New("missing exact manifest")
	got, err := CalculateCSIComposition(root.Identity, func(id AssemblyIdentity) (*AssemblyManifest, error) {
		if id.Name == "Root" {
			return root, nil
		}
		return nil, missing
	}, 0)
	if !errors.Is(err, missing) || got != nil {
		t.Fatalf("missing edge was hidden: %+v, %v", got, err)
	}
}

func TestCSICompositionBoundsAndUnsupportedEdges(t *testing.T) {
	for _, tc := range []struct {
		name, body, contains string
		limit                int
	}{
		{"cycle", compositionEdge("Root", "install"), "depth", 0},
		{"queue", compositionEdge("A", "install") + compositionEdge("B", "install"), "work limit", 2},
		{"selector", strings.ReplaceAll(compositionEdge("A", "install"), `language="neutral"`, `language="*"`), "exact identity", 0},
		{"unknown", compositionEdge("A", "future"), "dependency type", 0},
		{"impact", `<deployment impact="future"/>`, "impact", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := compositionFixture(t, "Root", tc.body)
			result, err := CalculateCSIComposition(root.Identity, func(id AssemblyIdentity) (*AssemblyManifest, error) { return root, nil }, tc.limit)
			if err == nil || !strings.Contains(err.Error(), tc.contains) || result != nil {
				t.Fatalf("result=%v err=%v", result, err)
			}
		})
	}
}
