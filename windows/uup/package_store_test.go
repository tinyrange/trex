package uup

import (
	"strings"
	"testing"

	"github.com/tinyrange/trex/archive/cab"
)

func TestAggregateTransportAliasesDoNotCollideInCBSStore(t *testing.T) {
	stage := &CumulativeStage{metadataCAB: &cab.Archive{}, Graph: &CumulativeGraph{Payloads: []DeltaPayload{{Target: ContentDescriptor{Name: "update.mum"}}, {Target: ContentDescriptor{Name: "update.cat"}}}}}
	paths := map[string]bool{}
	for _, name := range []string{"Package_for_ServicingStack", "Package_for_RollupFix"} {
		id := AssemblyIdentity{Name: name, Version: "10.0.26100.9711", ProcessorArchitecture: "amd64", PublicKeyToken: "31bf3856ad364e35", Language: "neutral"}
		plan, err := PlanStageEffects(stage, StageAssemblyPlan{Packages: []NamedAssemblyManifest{{Path: "update.mum", Manifest: &AssemblyManifest{Identity: id}}}})
		if err != nil {
			t.Fatal(err)
		}
		if len(plan.Files) != 2 {
			t.Fatalf("files=%+v", plan.Files)
		}
		for _, file := range plan.Files {
			if paths[file.StorePath] {
				t.Fatalf("aggregate transport aliases collided: %s", file.StorePath)
			}
			paths[file.StorePath] = true
			if !strings.HasPrefix(file.StorePath, "/Windows/servicing/Packages/"+name+"~31bf3856ad364e35~amd64~~10.0.26100.9711.") {
				t.Fatalf("noncanonical package path: %s", file.StorePath)
			}
			if file.Kind == "package-catalog" {
				if file.SourceName != "update.cat" || len(file.Destinations) != 1 || !strings.HasSuffix(file.Destinations[0], name+"~31bf3856ad364e35~amd64~~10.0.26100.9711.cat") {
					t.Fatalf("catalog transport/store conflated: %+v", file)
				}
			} else if file.SourceName != "update.mum" {
				t.Fatal("lost manifest transport alias")
			}
		}
	}
}
