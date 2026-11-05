package uup

import (
	"strings"
	"testing"
)

func TestCBSRootOwnerNativeSelection(t *testing.T) {
	id := cbsIntentManifest(t, "Root", "neutral", "").Identity
	name, _ := cbsPackageName(id)
	otherID := id
	otherID.Name = "Other"
	other, _ := cbsPackageName(otherID)
	lastID := id
	lastID.Name = "Last"
	last, _ := cbsPackageName(lastID)
	edge := func(owner string, integration, state uint32) CBSPackageOwnerIntent {
		return CBSPackageOwnerIntent{Package: name, Owner: owner, Integration: integration, State: state}
	}
	for _, tc := range []struct {
		name        string
		owners      []CBSPackageOwnerIntent
		explicit    string
		blr         bool
		want        string
		integration uint32
	}{
		{"new legacy", nil, "", false, name, 3},
		{"new BLR", nil, "", true, name, 2},
		{"ordinary installed owner", []CBSPackageOwnerIntent{edge(other, 2, 0x70)}, "", true, "", 0},
		{"zero-state self", []CBSPackageOwnerIntent{edge(strings.ToUpper(name), 2, 0)}, "", true, name, 2},
		{"permanent self preserves integration not state", []CBSPackageOwnerIntent{edge(name, 4, 0x80)}, "", true, name, 4},
		{"liberated legacy projects self", []CBSPackageOwnerIntent{edge(other, 4, 0x40)}, "", false, name, 3},
		{"liberated BLR retains owner", []CBSPackageOwnerIntent{edge(other, 4, 0x40)}, "", true, other, 4},
		{"last liberated wins", []CBSPackageOwnerIntent{edge(other, 4, 0x70), edge(last, 4, 0)}, "", true, last, 4},
		{"self wins after liberated", []CBSPackageOwnerIntent{edge(other, 4, 0x70), edge(name, 3, 0x40)}, "", true, name, 3},
		{"self stops before liberated", []CBSPackageOwnerIntent{edge(name, 2, 0x40), edge(other, 4, 0x70)}, "", true, name, 2},
		{"explicit overrides self", []CBSPackageOwnerIntent{edge(name, 2, 0x80)}, other, true, other, 3},
		{"explicit overrides ordinary ownership", []CBSPackageOwnerIntent{edge(last, 2, 0x70)}, other, false, other, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := PlanCBSRootPackageOwner(CBSRootPackageIntent{Identity: id, IntendedState: CBSStateStaged, Integration: 3, ExplicitOwner: tc.explicit, Owners: tc.owners, CBSBLREnabled: tc.blr})
			if err != nil {
				t.Fatal(err)
			}
			if tc.want == "" {
				if got != nil {
					t.Fatalf("unexpected root owner: %+v", got)
				}
				return
			}
			if got == nil || got.Package != name || got.Owner != tc.want || got.Integration != tc.integration || got.State != CBSStateStaged {
				t.Fatalf("got %+v, want owner %s integration %d state 0x40", got, tc.want, tc.integration)
			}
		})
	}
}

func TestCBSRootOwnerRejectsUnresolvedOrMalformedInputs(t *testing.T) {
	id := cbsIntentManifest(t, "Root", "neutral", "").Identity
	name, _ := cbsPackageName(id)
	valid := CBSPackageOwnerIntent{Package: name, Owner: name, Integration: 2, State: 0x70}
	for _, mutate := range []func(*CBSRootPackageIntent){
		func(in *CBSRootPackageIntent) { in.IntendedState = 0x1000 },
		func(in *CBSRootPackageIntent) { in.IntendedState = 0 },
		func(in *CBSRootPackageIntent) { in.Integration = 0 },
		func(in *CBSRootPackageIntent) { in.ExplicitOwner = "not-a-package" },
		func(in *CBSRootPackageIntent) { in.Owners = []CBSPackageOwnerIntent{valid, valid} },
		func(in *CBSRootPackageIntent) {
			bad := valid
			bad.Owner = strings.ToUpper(name)
			in.Owners = []CBSPackageOwnerIntent{valid, bad}
		},
		func(in *CBSRootPackageIntent) {
			bad := valid
			bad.Package = "unrelated"
			in.Owners = []CBSPackageOwnerIntent{bad}
		},
		func(in *CBSRootPackageIntent) {
			bad := valid
			bad.Owner = "malformed"
			in.Owners = []CBSPackageOwnerIntent{bad}
		},
		func(in *CBSRootPackageIntent) {
			bad := valid
			bad.Integration = 9
			in.Owners = []CBSPackageOwnerIntent{bad}
		},
		func(in *CBSRootPackageIntent) {
			bad := valid
			bad.State = 0x10000
			in.Owners = []CBSPackageOwnerIntent{bad}
		},
	} {
		in := CBSRootPackageIntent{Identity: id, IntendedState: CBSStateInstalled, Integration: 2}
		mutate(&in)
		if got, err := PlanCBSRootPackageOwner(in); err == nil || got != nil {
			t.Fatalf("got %+v, %v for %+v", got, err, in)
		}
	}
}
