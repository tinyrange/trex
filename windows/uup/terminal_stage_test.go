package uup

import (
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"strings"
	"sync"
	"testing"
)

func TestTerminalStageExactPredecessorBinding(t *testing.T) {
	const stem = "amd64_microsoft-windows-kernel32_31bf3856ad364e35_10.0.26100.9444_none_2f8379ba064efb69"
	const identity = "Microsoft-Windows-Kernel32, Culture=neutral, Version=10.0.26100.9444, PublicKeyToken=31bf3856ad364e35, ProcessorArchitecture=amd64, versionScope=nonSxS"
	const xml = `<assembly xmlns="urn:schemas-microsoft-com:asm.v3"><assemblyIdentity name="Microsoft-Windows-Kernel32" language="neutral" version="10.0.26100.9444" publicKeyToken="31bf3856ad364e35" processorArchitecture="amd64" versionScope="nonSxS"/></assembly>`
	oldStem := strings.Replace(stem, "10.0.26100.9444", "10.0.26100.1", 1)
	state, err := newAssemblyImageState(nil, []string{oldStem + ".manifest"})
	if err != nil {
		t.Fatal(err)
	}
	planner := &AssemblyPlanner{state: state, content: &assemblyContentState{}}
	stage := &CumulativeStage{} // No metadata archive: binding must not scan any XML.
	if err := planner.BindFinalStageContent(stage); err != nil {
		t.Fatal(err)
	}
	if err := planner.BindStageContent(&CumulativeStage{}); err == nil {
		t.Fatal("advanced sealed inventory")
	}
	if _, err := planner.PlanStage(&CumulativeStage{}); err == nil {
		t.Fatal("planned after seal")
	}
	if err := planner.BindFinalStageContent(&CumulativeStage{}); err == nil {
		t.Fatal("bound after seal")
	}
	index, err := newComponentMetadataIndex([]stageMetadataEntry{{Name: stem + ".manifest", Path: stem + ".manifest"}}, func(name string) (storage.Reader, error) {
		return &starfile.Bytes{Name: name, Data: []byte(xml)}, nil
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	index.bindPredecessor = stage.bindComponentPredecessor
	basis := &ContentDescriptor{Length: 7}
	if got := stage.nameExpressBasis(stem+`\file.dll`, basis); got != basis {
		t.Fatal("hint before exact resolution")
	}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				if _, ok, err := index.Open([]byte(identity)); err != nil || !ok {
					t.Errorf("resolve: %v %v", ok, err)
					return
				}
				got := stage.nameExpressBasis(stem+`\file.dll`, basis)
				if got.Name != oldStem+`\file.dll` || !got.nameHint || got.Length != basis.Length || got.SHA256 != basis.SHA256 {
					t.Errorf("basis: %+v", got)
					return
				}
			}
		}()
	}
	wg.Wait()
	if basis.Name != "" {
		t.Fatal("modified source descriptor")
	}
	// A corrupt manifest cannot publish a hint merely because its path matches.
	stage.predecessorByStem = nil
	index.open = func(name string) (storage.Reader, error) {
		return &starfile.Bytes{Data: []byte(strings.Replace(xml, "nonSxS", "SxS", 1))}, nil
	}
	if _, _, err := index.Open([]byte(identity)); err == nil {
		t.Fatal("accepted wrong identity")
	}
	if got := stage.nameExpressBasis(stem+`\file.dll`, basis); got != basis {
		t.Fatal("published corrupt hint")
	}
}
