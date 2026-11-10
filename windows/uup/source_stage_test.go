package uup

import (
	"strings"
	"testing"
)

func TestSourceStageLineageDoesNotReadOrAdmitPackages(t *testing.T) {
	const stem = "amd64_microsoft-windows-kernel32_31bf3856ad364e35_10.0.26100.9444_none_2f8379ba064efb69"
	old := strings.Replace(stem, "9444", "1", 1)
	state, err := newAssemblyImageState(nil, []string{old + ".manifest"})
	if err != nil {
		t.Fatal(err)
	}
	planner := &AssemblyPlanner{state: state, content: &assemblyContentState{}}
	makeStage := func(name string) *CumulativeStage {
		// Metadata names exist but no archive or PSF bytes can be opened. Binding
		// must not decode either component manifests or the aggregate package.
		return &CumulativeStage{metadataArchives: []stageMetadataArchive{{name: "empty"}}, Graph: &CumulativeGraph{Payloads: []DeltaPayload{
			{Target: ContentDescriptor{Name: name + ".manifest"}},
			{Target: ContentDescriptor{Name: "update.mum"}},
		}}}
	}
	first := makeStage(stem)
	if err := planner.BindSourceStageContent(first); err != nil {
		t.Fatal(err)
	}
	laterStem := strings.Replace(stem, "9444", "9500", 1)
	second := makeStage(laterStem)
	if err := planner.BindSourceStageContent(second); err != nil {
		t.Fatal(err)
	}
	basis := &ContentDescriptor{Length: 7, SHA256: [32]byte{42}}
	for _, row := range []struct {
		stage            *CumulativeStage
		target, previous string
	}{{first, stem, old}, {second, laterStem, stem}} {
		got := row.stage.nameExpressBasis(row.target+"/file.dll", basis)
		if got.Name != row.previous+`\file.dll` || got.Length != basis.Length || got.SHA256 != basis.SHA256 || !got.nameHint {
			t.Fatalf("wrong immutable predecessor hint: %+v", got)
		}
	}
	if len(planner.state.packagesByExact) != 0 || len(planner.ownershipComponents) != 0 {
		t.Fatal("source inventory became admission")
	}
	if _, err := planner.PlanStage(makeStage(laterStem)); err == nil {
		t.Fatal("mixed source inventory with admission")
	}
	if err := planner.BindFinalStageContent(makeStage(laterStem)); err == nil {
		t.Fatal("mixed source inventory with terminal admission state")
	}
}
