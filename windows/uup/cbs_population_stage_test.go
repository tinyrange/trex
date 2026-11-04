package uup

import (
	"strings"
	"testing"
)

func TestCBSOrdinaryStageOnlyPreservesOwnersAndCapsNewUpdates(t *testing.T) {
	for _, start := range []uint32{0, CBSStateStaged, CBSStateSuperseded, CBSStateInstalled} {
		root := cbsIntentManifest(t, "Root", "neutral", `<update name="existing"/>`)
		child := cbsIntentManifest(t, "Child", "neutral", `<update name="payload"/>`)
		grand := cbsIntentManifest(t, "Grand", "neutral", `<update name="payload"/>`)
		root.References = []AssemblyReference{{Kind: "package", Identity: child.Identity, UpdateName: "existing"}}
		child.References = []AssemblyReference{{Kind: "package", Identity: grand.Identity, UpdateName: "payload"}}
		index, err := NewCBSUpdateStateIndex([]CBSPackageIntent{{Manifest: root, IntendedState: CBSStateInstalled}, {Manifest: child, IntendedState: CBSStateInstalled}, {Manifest: grand}})
		if err != nil {
			t.Fatal(err)
		}
		request := populationRequest(t, root, CBSStateStaged)
		request.StageOnly = true
		stores := []CBSPackageOwnerIntent{{Package: request.Owner, Owner: request.Owner, State: CBSStateInstalled, Integration: 2}}
		policy := populationPolicy()
		policy.Watch = ordinaryWatchPolicy()
		policy.Watch.InitialUpdate = func(id AssemblyIdentity, _ string, _ uint32, _ *CBSUpdateStateIndex) (CBSOrdinaryUpdateStart, error) {
			state := uint32(CBSStateInstalled)
			if id.Name == "Child" {
				state = start
			}
			if id.Name == "Grand" {
				state = 0
			}
			return CBSOrdinaryUpdateStart{State: state, HasDeployments: true}, nil
		}
		result, err := PlanCBSOrdinaryPopulation(index, stores, []CBSOrdinaryRequest{request}, policy)
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Executions) != 3 {
			t.Fatal(result.Executions)
		}
		first, second, third := result.Executions[0], result.Executions[1], result.Executions[2]
		if first.IntendedState != CBSStateInstalled || first.Owners[0].State != CBSStateInstalled || first.Updates["existing"] != CBSStateInstalled {
			t.Fatalf("staging lowered resident owner/update: %+v", first)
		}
		want := uint32(CBSStateInstalled)
		if start <= CBSStateStaged {
			want = CBSStateStaged
		}
		if second.Updates["payload"] != want || third.IntendedState != want || third.Owners[0].State != want {
			t.Fatalf("start %#x: child propagation mismatch: %+v %+v", start, second, third)
		}
		if third.Updates["payload"] != CBSStateStaged {
			t.Fatalf("stage-only flag lost across child reference: %+v", third)
		}
		published, err := result.Index.UpdateState(child.Identity, "payload")
		if err != nil || published.IntendedState != want {
			t.Fatal(published, err)
		}
		if before := index.PackageIntendedStates()[request.Owner]; before != CBSStateInstalled {
			t.Fatal(before)
		}
	}
}

func TestCBSOrdinaryStageOnlyRejectsUnknownUpdateStarts(t *testing.T) {
	root := cbsIntentManifest(t, "Root", "neutral", `<update name="payload"/>`)
	index, err := NewCBSUpdateStateIndex([]CBSPackageIntent{{Manifest: root}})
	if err != nil {
		t.Fatal(err)
	}
	request := populationRequest(t, root, CBSStateStaged)
	request.StageOnly = true
	_, err = PlanCBSOrdinaryPopulation(index, nil, []CBSOrdinaryRequest{request}, populationPolicy())
	if err == nil || !strings.Contains(err.Error(), "update start states") {
		t.Fatal(err)
	}
}
