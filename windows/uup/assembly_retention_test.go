package uup

import (
	"runtime"
	"testing"
	"weak"

	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
)

// Lazy readers outlive construction. They must preserve their lookup data,
// without keeping the planner and its unrelated admission graphs alive.
func TestDictionaryResolverReleasesConstructionState(t *testing.T) {
	resolver, parent := func() (func() (storage.Reader, error), weak.Pointer[assemblyContentState]) {
		state := &assemblyContentState{}
		resolver := state.dictionaryResolver()
		// Seed the shared memoized result without requiring a WIM fixture.
		state.dictionary.once.Do(func() {
			state.dictionary.file = &starfile.Bytes{Name: "dictionary", Data: []byte("dictionary bytes")}
		})
		return resolver, weak.Make(state)
	}()
	runtime.GC()
	if parent.Value() != nil {
		t.Fatal("dictionary reader retains construction state")
	}
	a, err := resolver()
	if err != nil || a == nil {
		t.Fatalf("dictionary: %v, %v", a, err)
	}
	b, err := resolver()
	if err != nil || a != b {
		t.Fatal("dictionary memoization lost")
	}
	runtime.KeepAlive(resolver)
}

func TestTerminalBindingReleasesAdmissionState(t *testing.T) {
	const oldStem = "amd64_microsoft-windows-kernel32_31bf3856ad364e35_10.0.26100.1_none_2f8379ba064efb69"
	stage, parent := func() (*CumulativeStage, weak.Pointer[assemblyImageState]) {
		state, err := newAssemblyImageState(nil, []string{oldStem + ".manifest"})
		if err != nil {
			t.Fatal(err)
		}
		planner := &AssemblyPlanner{state: state, content: &assemblyContentState{}}
		stage := &CumulativeStage{}
		if err := planner.BindFinalStageContent(stage); err != nil {
			t.Fatal(err)
		}
		return stage, weak.Make(state)
	}()
	runtime.GC()
	if parent.Value() != nil {
		t.Fatal("terminal reader retains admission state")
	}
	component, _, err := ParseComponentContentName(oldStem + "/file.dll")
	if err != nil {
		t.Fatal(err)
	}
	stage.bindComponentPredecessor(component.Identity, "updated")
	if got := stage.predecessorByStem["updated"]; got != oldStem {
		t.Fatalf("predecessor after GC = %q, want %q", got, oldStem)
	}
	runtime.KeepAlive(stage)
}
