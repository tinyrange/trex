package uup

import (
	"crypto/sha256"
	"fmt"
	"io"
	"reflect"
	"testing"

	"github.com/tinyrange/trex/archive/wim"
	"github.com/tinyrange/trex/storage"
	bytecache "github.com/tinyrange/trex/storage/cache"
	starfile "github.com/tinyrange/trex/storage/star"
)

func TestPlannedReadOrderReusesChunksWithoutChangingResults(t *testing.T) {
	files := make([]StageFileEffect, 6)
	for i := range files {
		digest := sha256.Sum256([]byte{byte(i % 3), 0, 0, 0})
		files[i] = StageFileEffect{SourceMode: "installed", SourceName: fmt.Sprint(i), StorePath: fmt.Sprint(i), ExpectedSHA256: &digest}
	}
	run := func(grouped bool) ([][]byte, uint64) {
		cache := bytecache.New(8) // Two of three four-byte source chunks fit.
		stage := &CumulativeStage{}
		stage.assemblyNameReadOrder = func(name string) (wim.FileReadOrder, bool) {
			var i int
			fmt.Sscan(name, &i)
			return wim.FileReadOrder{Source: 1, BlobOffset: int64(i%3) * 4}, true
		}
		stage.assemblyNameResolver = func(name string) (storage.Reader, error) {
			var i int
			fmt.Sscan(name, &i)
			data, err := cache.Get(bytecache.Key{Index: i % 3}, func() ([]byte, error) { return []byte{byte(i % 3), 0, 0, 0}, nil })
			return &starfile.Bytes{Name: name, Data: data}, err
		}
		order := []int{0, 1, 2, 3, 4, 5}
		if grouped {
			order = stage.PlannedFileReadOrder(files)
		}
		if cache.Stats().Loads != 0 {
			t.Fatal("ordering read source bytes")
		}
		results := make([][]byte, len(files))
		for _, i := range order {
			f, err := stage.OpenPlannedFile(files[i])
			if err != nil {
				t.Fatal(err)
			}
			results[i], err = io.ReadAll(io.NewSectionReader(f, 0, f.Size()))
			if err != nil {
				t.Fatal(err)
			}
		}
		bad := files[0]
		bad.ExpectedSHA256 = &[32]byte{}
		if _, err := stage.OpenPlannedFile(bad); err == nil {
			t.Fatal("ordering bypassed file hash verification")
		}
		return results, cache.Stats().Loads
	}
	plain, plainLoads := run(false)
	grouped, groupedLoads := run(true)
	// The final intentional bad-hash read adds one reload after the plain run.
	if !reflect.DeepEqual(plain, grouped) || plainLoads != 7 || groupedLoads != 4 {
		t.Fatalf("results equal=%v, loads plain=%d grouped=%d", reflect.DeepEqual(plain, grouped), plainLoads, groupedLoads)
	}
}

func TestReadOrderFollowsExactPredecessorIdentityAndKeepsUnknowns(t *testing.T) {
	basis := ContentDescriptor{Name: "base", Length: 4, SHA256: sha256.Sum256([]byte("base"))}
	target := ContentDescriptor{Name: "target", Length: 4, SHA256: sha256.Sum256([]byte("next"))}
	prior := &CumulativeStage{Graph: &CumulativeGraph{Payloads: []DeltaPayload{{Target: target, Basis: &basis}}},
		expressByTarget: map[string]DeltaPayload{"target": {Target: target, Basis: &basis}}}
	prior.assemblyReadOrder = func(d ContentDescriptor) (wim.FileReadOrder, bool) {
		if d != basis {
			t.Fatalf("wrong basis: %+v", d)
		}
		return wim.FileReadOrder{Source: 7, BlobOffset: 64}, true
	}
	state := &assemblyContentState{prior: []completedAssemblyStage{{stage: prior}}}
	stage := &CumulativeStage{assemblyReadOrder: state.snapshotReadOrder()}
	wrong := target
	wrong.SHA256 = [32]byte{}
	files := []StageFileEffect{
		{SourceMode: "predecessor", SourceDescriptor: &wrong},
		{SourceMode: "predecessor", SourceDescriptor: &target},
		{SourceMode: "metadata"},
	}
	if got := stage.PlannedFileReadOrder(files); !reflect.DeepEqual(got, []int{1, 0, 2}) {
		t.Fatalf("order = %v", got)
	}
}

func TestCarryIndexPreservesFirstAliasAndStrictResolver(t *testing.T) {
	first := ContentDescriptor{Name: "first", Length: 4, SHA256: sha256.Sum256([]byte("base"))}
	second := first
	second.Name = "second"
	stage := &CumulativeStage{Graph: &CumulativeGraph{Carries: []CarryPayload{
		{Target: ContentDescriptor{Name: "Component/File.dll"}, Source: first},
		{Target: ContentDescriptor{Name: `component\file.dll`}, Source: second},
	}}}
	stage.assemblyResolver = func(d ContentDescriptor) (storage.Reader, error) {
		if d != first {
			t.Fatalf("wrong carry descriptor: %+v", d)
		}
		return nil, fmt.Errorf("strict source verification failed")
	}
	if !stage.hasContentTarget(`COMPONENT\FILE.DLL`) || stage.hasContentTarget("missing") {
		t.Fatal("indexed carry lookup changed name matching")
	}
	if _, err := stage.OpenContentTarget("component/file.dll"); err == nil || err.Error() != "strict source verification failed" {
		t.Fatalf("carry resolver error = %v", err)
	}
}
