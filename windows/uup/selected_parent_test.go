package uup

import "testing"

// A newly selected root can satisfy a checkpoint parent even when the installed
// root is older than that checkpoint. Matching only the selected exact key loses
// the child; relaxing the identity would install another architecture's child.
func TestSelectedCheckpointParentClosesPackageGraph(t *testing.T) {
	for _, tc := range []struct {
		name, arch, checkpoint string
		want                   int
	}{
		{"new selected parent", "amd64", "10.0.26100.1742", 2},
		{"future checkpoint", "amd64", "10.0.26100.9800", 1},
		{"different architecture", "arm64", "10.0.26100.1742", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state, err := newAssemblyImageState([]string{"root~token~amd64~~10.0.26100.1.mum"}, nil)
			if err != nil {
				t.Fatal(err)
			}
			root := AssemblyIdentity{Name: "root", PublicKeyToken: "token", ProcessorArchitecture: "amd64", Version: "10.0.26100.9711"}
			child := root
			child.Name = "child"
			parent := root
			parent.Version = tc.checkpoint
			parent.ProcessorArchitecture = tc.arch
			rootPath := manifestPath{Path: "root.mum", Identity: root}
			childPath := manifestPath{Path: "child.mum", Identity: child}
			catalog := &stageManifestCatalog{
				stage:            &CumulativeStage{},
				packagesByStable: map[string][]manifestPath{root.StableKey(): {rootPath}},
				packagesByExact:  map[string]manifestPath{child.ExactKey(): childPath},
				parsedPackages: map[string]*AssemblyManifest{
					"root.mum":  {Identity: root, References: []AssemblyReference{{Kind: "package", Identity: child}}},
					"child.mum": {Identity: child, References: []AssemblyReference{{Kind: "parent", Identity: parent, Attributes: []ManifestAttribute{{Name: "revisionCompare", Value: "GE"}}}}},
				},
			}
			plan, err := catalog.plan(state)
			if err != nil {
				t.Fatal(err)
			}
			if len(plan.Packages) != tc.want {
				t.Fatalf("selected %d packages, want %d", len(plan.Packages), tc.want)
			}
		})
	}
}
