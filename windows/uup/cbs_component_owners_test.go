package uup

import (
	"reflect"
	"strings"
	"testing"
)

func TestCBSComponentOwnerReduction(t *testing.T) {
	a := CBSComponentOwner{Name: "Package_A.Update", Elevation: 128}
	b := CBSComponentOwner{Name: a.Name, Elevation: 8}
	c := CBSComponentOwner{Name: "package_a.Update", Elevation: 128}
	rtm := CBSComponentOwner{Anonymous: true, Elevation: 2}
	cases := []struct {
		name              string
		base              CBSComponentOwners
		changes           []CBSComponentOwnerChange
		installed, pinned []CBSComponentOwner
		bad               bool
	}{
		{name: "distinct elevations and case", base: CBSComponentOwners{Installed: []CBSComponentOwner{a}}, changes: []CBSComponentOwnerChange{{a, "install"}, {b, "install"}, {c, "install"}}, installed: []CBSComponentOwner{a, b, c}},
		{name: "pin is not install", changes: []CBSComponentOwnerChange{{a, "pin"}}, pinned: []CBSComponentOwner{a}},
		{name: "remove exact before anonymous", base: CBSComponentOwners{Installed: []CBSComponentOwner{rtm, a, b}}, changes: []CBSComponentOwnerChange{{a, "uninstall"}}, installed: []CBSComponentOwner{rtm, b}},
		{name: "missing exact consumes RTM", base: CBSComponentOwners{Installed: []CBSComponentOwner{rtm, b}}, changes: []CBSComponentOwnerChange{{a, "uninstall"}}, installed: []CBSComponentOwner{b}},
		{name: "wrong elevation is missing", base: CBSComponentOwners{Installed: []CBSComponentOwner{b}}, changes: []CBSComponentOwnerChange{{a, "uninstall"}}, bad: true},
		{name: "cumulative duplicate not replayed", changes: []CBSComponentOwnerChange{{a, "install"}, {a, "uninstall"}, {a, "install"}}},
		{name: "remove then add stays installed", base: CBSComponentOwners{Installed: []CBSComponentOwner{a, b}}, changes: []CBSComponentOwnerChange{{a, "uninstall"}, {a, "install"}}, installed: []CBSComponentOwner{b, a}},
		{name: "unpin preserves installed", base: CBSComponentOwners{Installed: []CBSComponentOwner{a}, Pinned: []CBSComponentOwner{a}}, changes: []CBSComponentOwnerChange{{a, "unpin"}}, installed: []CBSComponentOwner{a}},
		{name: "cannot consume pin for uninstall", base: CBSComponentOwners{Pinned: []CBSComponentOwner{rtm}}, changes: []CBSComponentOwnerChange{{a, "uninstall"}}, bad: true},
		{name: "missing remove fails", changes: []CBSComponentOwnerChange{{a, "uninstall"}}, bad: true},
		{name: "anonymous change rejected", changes: []CBSComponentOwnerChange{{rtm, "install"}}, bad: true},
		{name: "invalid action rejected", changes: []CBSComponentOwnerChange{{a, "stage"}}, bad: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ResolveCBSComponentOwners(tc.base, tc.changes)
			if tc.bad {
				if err == nil {
					t.Fatal("accepted invalid ownership")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(got.Installed) != len(tc.installed) || len(got.Pinned) != len(tc.pinned) {
				t.Fatalf("got %#v", got)
			}
			if len(tc.installed) > 0 && !reflect.DeepEqual(got.Installed, tc.installed) {
				t.Fatalf("installed %#v", got.Installed)
			}
			if len(tc.pinned) > 0 && !reflect.DeepEqual(got.Pinned, tc.pinned) {
				t.Fatalf("pinned %#v", got.Pinned)
			}
		})
	}
	base := CBSComponentOwners{Installed: []CBSComponentOwner{a}}
	got, err := ResolveCBSComponentOwners(base, nil)
	if err != nil {
		t.Fatal(err)
	}
	got.Installed[0] = b
	if base.Installed[0] != a {
		t.Fatal("result aliased baseline")
	}
	for _, o := range []CBSComponentOwner{{Name: "bad", Elevation: 16}, {Name: "x", Anonymous: true, Elevation: 2}, {Name: "bad\x00name", Elevation: 128}, {Name: string([]byte{255}), Elevation: 128}, {Name: strings.Repeat("a", (64<<10)+1), Elevation: 128}} {
		if _, err := ResolveCBSComponentOwners(CBSComponentOwners{Installed: []CBSComponentOwner{o}}, nil); err == nil {
			t.Fatalf("accepted invalid source %#v", o.Elevation)
		}
	}
}

func TestCBSComponentOwnerOverlayApplicability(t *testing.T) {
	identity := []byte("NetFx, Culture=neutral, Version=4.0.15912.0, PublicKeyToken=b03f5f7f11d50a3a, ProcessorArchitecture=x86")
	target := AssemblyIdentity{Name: "NetFx", Version: "4.0.15920.116", PublicKeyToken: "b03f5f7f11d50a3a", ProcessorArchitecture: "x86", Language: "neutral"}
	owner := CBSComponentOwner{Name: "Package.Update", Elevation: 128}
	for _, tc := range []struct {
		action   string
		expected bool
	}{{"pin", false}, {"install", true}} {
		owners, err := ResolveCBSComponentOwners(CBSComponentOwners{}, []CBSComponentOwnerChange{{owner, tc.action}})
		if err != nil {
			t.Fatal(err)
		}
		entry := CBSComponentInventoryEntry{Identity: identity}
		for _, o := range owners.Installed {
			entry.Owners = append(entry.Owners, o.Elevation)
		}
		index, err := NewCBSComponentStateIndex([]CBSComponentInventoryEntry{entry})
		if err != nil {
			t.Fatal(err)
		}
		applicable, err := index.SelfUpdate(target, "build")
		if err != nil || applicable != tc.expected {
			t.Fatalf("%s: %v %v", tc.action, applicable, err)
		}
	}
}
