package uup

import (
	"reflect"
	"strings"
	"testing"
)

func TestCBSAdmissionOwnerPrecedenceAndCaps(t *testing.T) {
	id := cbsIntentManifest(t, "Child", "neutral", "").Identity
	name, _ := cbsPackageName(id)
	other := id
	other.Name = "Wrapper"
	wrapper, _ := cbsPackageName(other)
	edge := func(owner string, state uint32) CBSPackageOwnerIntent {
		return CBSPackageOwnerIntent{Package: name, Owner: owner, Integration: 2, State: state}
	}
	for _, tc := range []struct {
		name                         string
		store, execution             []CBSPackageOwnerIntent
		owner                        string
		request, ceiling, applicable uint32
		preserve, bypass             bool
		want                         CBSAdmissionState
	}{
		{
			name:    "watch-list request does not install an ownerless package",
			request: 0x1000, ceiling: 0x1000, applicable: 0x70,
			want: CBSAdmissionState{0x1000, 0, 0, 0},
		},
		{
			name:    "ownerless concrete fallback",
			request: 0x40, ceiling: 0x1000, applicable: 0x70,
			want: CBSAdmissionState{0x40, 0x40, 0x40, 0x40},
		},
		{
			name:    "supersedence target leaves permanent self owner intact",
			store:   []CBSPackageOwnerIntent{edge(name, 0x80)},
			request: 0x50, ceiling: 0x1000, applicable: 0x50,
			want: CBSAdmissionState{0x50, 0x70, 0x70, 0x50},
		},
		{
			name:    "ownerless request cannot override existing owners",
			store:   []CBSPackageOwnerIntent{edge(wrapper, 0x40)},
			request: 0x70, ceiling: 0x1000, applicable: 0x70,
			want: CBSAdmissionState{0x70, 0x40, 0x40, 0x40},
		},
		{
			name:    "zero owner still counts as an owner",
			store:   []CBSPackageOwnerIntent{edge(wrapper, 0)},
			request: 0x70, ceiling: 0x1000, applicable: 0x70,
			want: CBSAdmissionState{0x70, 0, 0, 0},
		},
		{
			name:      "execution replacement is not a historical maximum",
			store:     []CBSPackageOwnerIntent{edge(wrapper, 0x70)},
			execution: []CBSPackageOwnerIntent{edge(strings.ToUpper(wrapper), 0x40)},
			request:   0x1000, ceiling: 0x1000, applicable: 0x70,
			want: CBSAdmissionState{0x1000, 0x40, 0x40, 0x40},
		},
		{
			name:      "explicit request wins over both layers",
			store:     []CBSPackageOwnerIntent{edge(wrapper, 0x70)},
			execution: []CBSPackageOwnerIntent{edge(wrapper, 0x50)},
			owner:     strings.ToUpper(wrapper), request: 0x40, ceiling: 0x1000, applicable: 0x70,
			want: CBSAdmissionState{0x40, 0x40, 0x40, 0x40},
		},
		{
			name:  "different owner retains installation",
			store: []CBSPackageOwnerIntent{edge(name, 0x80), edge(wrapper, 0x70)},
			owner: wrapper, request: 0x40, ceiling: 0x1000, applicable: 0x70,
			want: CBSAdmissionState{0x40, 0x70, 0x70, 0x70},
		},
		{
			name:  "caller ceiling and applicability are distinct caps",
			store: []CBSPackageOwnerIntent{edge(wrapper, 0x70)},
			owner: wrapper, request: 0x70, ceiling: 0x50, applicable: 0x40,
			want: CBSAdmissionState{0x70, 0x70, 0x50, 0x40},
		},
		{
			name:      "preserve raises request from store not execution",
			store:     []CBSPackageOwnerIntent{edge(wrapper, 0x70)},
			execution: []CBSPackageOwnerIntent{edge(wrapper, 0x50)},
			owner:     wrapper, request: 0x40, ceiling: 0x1000, applicable: 0x40, preserve: true,
			want: CBSAdmissionState{0x70, 0x70, 0x70, 0x40},
		},
		{
			name:      "preserve does not retain an execution-only higher request",
			store:     []CBSPackageOwnerIntent{edge(wrapper, 0x40)},
			execution: []CBSPackageOwnerIntent{edge(wrapper, 0x70)},
			owner:     wrapper, request: 0x40, ceiling: 0x1000, applicable: 0x70, preserve: true,
			want: CBSAdmissionState{0x40, 0x40, 0x40, 0x40},
		},
		{
			name:    "bypass supports explicit removal despite permanent owner",
			store:   []CBSPackageOwnerIntent{edge(name, 0x80)},
			request: 0, ceiling: 0x1000, applicable: 0x70, bypass: true,
			want: CBSAdmissionState{0, 0, 0, 0},
		},
		{
			name:    "bypass still respects applicability",
			store:   []CBSPackageOwnerIntent{edge(wrapper, 0x40)},
			request: 0x70, ceiling: 0x50, applicable: 0x40, bypass: true,
			want: CBSAdmissionState{0x70, 0x70, 0x50, 0x40},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := CBSPackageAdmission{Identity: id, StoreOwners: tc.store, ExecutionOwners: tc.execution,
				Owner: tc.owner, RequestedState: tc.request, Ceiling: tc.ceiling, ApplicableState: tc.applicable,
				PreserveStoreOwner: tc.preserve, BypassOwners: tc.bypass}
			store := append([]CBSPackageOwnerIntent(nil), tc.store...)
			execution := append([]CBSPackageOwnerIntent(nil), tc.execution...)
			got, err := ResolveCBSPackageAdmission(in)
			if err != nil || got == nil || *got != tc.want {
				t.Fatalf("got %+v, %v; want %+v", got, err, tc.want)
			}
			if !reflect.DeepEqual(store, in.StoreOwners) || !reflect.DeepEqual(execution, in.ExecutionOwners) {
				t.Fatal("admission mutated input owner layers")
			}
		})
	}
}

func TestCBSAdmissionRejectsUnresolvedInputs(t *testing.T) {
	id := cbsIntentManifest(t, "Child", "neutral", "").Identity
	name, _ := cbsPackageName(id)
	edge := CBSPackageOwnerIntent{Package: name, Owner: name, Integration: 2, State: 0x70}
	for _, tc := range []struct {
		name   string
		change func(*CBSPackageAdmission)
	}{
		{"pending request", func(in *CBSPackageAdmission) { in.RequestedState = 0x60 }},
		{"pending ceiling", func(in *CBSPackageAdmission) { in.Ceiling = 5 }},
		{"unresolved applicability", func(in *CBSPackageAdmission) { in.ApplicableState = 0x1000 }},
		{"unspecified owner request", func(in *CBSPackageAdmission) { in.Owner = name }},
		{"unspecified bypass", func(in *CBSPackageAdmission) { in.BypassOwners = true }},
		{"malformed owner", func(in *CBSPackageAdmission) { in.Owner = "not-an-identity" }},
		{"duplicate store owner", func(in *CBSPackageAdmission) { in.StoreOwners = []CBSPackageOwnerIntent{edge, edge} }},
		{"case duplicate execution owner", func(in *CBSPackageAdmission) {
			other := edge
			other.Owner = strings.ToUpper(name)
			in.ExecutionOwners = []CBSPackageOwnerIntent{edge, other}
		}},
		{"foreign owner package", func(in *CBSPackageAdmission) {
			other := edge
			other.Package = "Other~31bf3856ad364e35~amd64~~1.0.0.0"
			in.StoreOwners = []CBSPackageOwnerIntent{other}
		}},
		{"pending owner", func(in *CBSPackageAdmission) {
			other := edge
			other.State = 0x60
			in.StoreOwners = []CBSPackageOwnerIntent{other}
		}},
		{"unknown integration", func(in *CBSPackageAdmission) {
			other := edge
			other.Integration = 5
			in.ExecutionOwners = []CBSPackageOwnerIntent{other}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := CBSPackageAdmission{Identity: id, RequestedState: 0x1000, Ceiling: 0x1000, ApplicableState: 0x70}
			tc.change(&in)
			if got, err := ResolveCBSPackageAdmission(in); err == nil || got != nil {
				t.Fatalf("got %+v, %v for %+v", got, err, in)
			}
		})
	}
}
