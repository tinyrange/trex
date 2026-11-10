package uup

import (
	"crypto/sha256"
	"github.com/tinyrange/trex/archive/wim"
	"sync"
	"testing"
)

func TestReadOrderSnapshotsPreservePrecedenceAndHistory(t *testing.T) {
	target := ContentDescriptor{Name: "alias", Length: 4, SHA256: sha256.Sum256([]byte("same"))}
	makeStage := func(source uint64, known bool) *CumulativeStage {
		stage := &CumulativeStage{Graph: &CumulativeGraph{}, expressByTarget: map[string]*DeltaPayload{}}
		for i, name := range []string{"first", "alias"} {
			d := target
			d.Name = name
			basis := d
			basis.Length = int64(i)
			p := DeltaPayload{Target: d, Basis: &basis}
			stage.Graph.Payloads = append(stage.Graph.Payloads, p)
			stage.expressByTarget[name] = &p
		}
		// An exact carry-name match must not displace payload candidates.
		carry := target
		carry.Name = "carry"
		stage.Graph.Carries = []CarryPayload{{Target: carry, Source: carry}}
		stage.assemblyReadOrder = func(d ContentDescriptor) (wim.FileReadOrder, bool) {
			return wim.FileReadOrder{Source: source, BlobOffset: d.Length}, known
		}
		return stage
	}
	old := makeStage(1, true)
	state := &assemblyContentState{prior: []completedAssemblyStage{{stage: old}}}
	early := state.snapshotReadOrder()
	state.prior = append(state.prior, completedAssemblyStage{stage: makeStage(2, true)})
	later := state.snapshotReadOrder()
	state.prior = append(state.prior, completedAssemblyStage{stage: makeStage(3, false)})
	unknown := state.snapshotReadOrder()
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, item := range []struct {
				lookup func(ContentDescriptor) (wim.FileReadOrder, bool)
				source uint64
			}{{early, 1}, {later, 2}} {
				for _, name := range []string{"ALIAS", "carry", "unmatched"} {
					d := target
					d.Name = name
					got, ok := item.lookup(d)
					wantOffset := int64(0)
					if name == "ALIAS" {
						wantOffset = 1
					}
					if !ok || got.Source != item.source || got.BlobOffset != wantOffset {
						t.Errorf("%s: %+v %v", name, got, ok)
					}
				}
			}
			if _, ok := unknown(target); ok {
				t.Error("unknown newest stage fell through")
			}
			wrong := target
			wrong.Length++
			if _, ok := later(wrong); ok {
				t.Error("wrong identity matched")
			}
		}()
	}
	wg.Wait()
}
