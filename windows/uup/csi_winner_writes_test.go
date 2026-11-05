package uup

import (
	"bytes"
	"github.com/tinyrange/trex/windows/registry"
	"reflect"
	"testing"
)

const winnerWriteIdentity = "Example, Culture=neutral, Version=1.0.1.0, PublicKeyToken=31bf3856ad364e35, ProcessorArchitecture=amd64"

func TestCSIWinnerWritesPreserveOtherDefaults(t *testing.T) {
	plan, err := PlanCSIWinnerWrites([]byte(winnerWriteIdentity+", versionScope=NonSxS"), "1.0.1.0", []string{"1.0.1.0", "0.9.1.0"}, []CSIWinnerVersionChange{{Version: "2.0.1.0", Installed: true, ImpactfulInstall: true}})
	if err != nil {
		t.Fatal(err)
	}
	// A cross-branch winner changes the selector and NEW branch default only.
	values := map[string]map[string]registry.Value{
		"":    {"": csiWinnerString("1.0")},
		"0.9": {"": csiWinnerString("0.9.1.0"), "0.9.1.0": {Type: 3, Data: []byte{1}}},
		"1.0": {"": csiWinnerString("1.0.1.0"), "1.0.1.0": {Type: 3, Data: []byte{1}}},
	}
	applyWinnerEdits(values, plan.Edits)
	if len(plan.Edits) != 3 || plan.Change.Winner != "2.0.1.0" || plan.Change.Shadowed != "1.0.1.0" {
		t.Fatalf("%+v", plan)
	}
	for branch, want := range map[string]string{"": "2.0", "0.9": "0.9.1.0", "1.0": "1.0.1.0", "2.0": "2.0.1.0"} {
		if !reflect.DeepEqual(values[branch][""], csiWinnerString(want)) {
			t.Fatalf("default changed incorrectly: %s: %+v", branch, values[branch][""])
		}
	}
	member := values["2.0"]["2.0.1.0"]
	if member.Type != 3 || !bytes.Equal(member.Data, []byte{1}) {
		t.Fatal(member)
	}
}

func TestCSIWinnerWritesClearOnlySelectedValues(t *testing.T) {
	for _, suffix := range []string{"", ", versionScope=NonSxS", ", Type=win32-policy"} {
		plan, err := PlanCSIWinnerWrites([]byte(winnerWriteIdentity+suffix), "1.0.1.0", []string{"1.0.1.0"}, []CSIWinnerVersionChange{{Version: "1.0.1.0", Installed: false, ImpactfulInstall: true}})
		if err != nil {
			t.Fatal(err)
		}
		values := map[string]map[string]registry.Value{
			"":    {"": csiWinnerString("1.0"), "unrelated": {Type: 3, Data: []byte{9}}},
			"1.0": {"": csiWinnerString("1.0.1.0"), "1.0.1.0": {Type: 3, Data: []byte{1}}},
			"2.0": {"": csiWinnerString("2.0.5.0")},
		}
		applyWinnerEdits(values, plan.Edits)
		if _, ok := values["1.0"]; !ok || len(values["1.0"]) != 0 {
			t.Fatal("removed key or left selected values", values)
		}
		_, selector := values[""][""]
		if selector != (suffix == "") {
			t.Fatal("wrong family selector removal", suffix, values)
		}
		if len(values["2.0"]) != 1 || len(values[""]["unrelated"].Data) != 1 {
			t.Fatal("unrelated state removed")
		}
	}
}

func TestCSIWinnerWritesMembershipWithoutDefault(t *testing.T) {
	// Nonimpactful membership must not conjure a default when there was none.
	plan, err := PlanCSIWinnerWrites([]byte(winnerWriteIdentity), "", nil, []CSIWinnerVersionChange{{Version: "1.0.2.0", Installed: true}})
	if err != nil || len(plan.Edits) != 1 || plan.Change != (CSIWinnerChange{}) || plan.Edits[0].Value.Name != "1.0.2.0" {
		t.Fatalf("%+v %v", plan, err)
	}
	// Another installed source leaving the component active is not a removal.
	plan, err = PlanCSIWinnerWrites([]byte(winnerWriteIdentity), "1.0.1.0", []string{"1.0.1.0"}, []CSIWinnerVersionChange{{Version: "1.0.1.0", Installed: true, ImpactfulInstall: true}})
	if err != nil || len(plan.Edits) != 0 {
		t.Fatalf("%+v %v", plan, err)
	}
}

func TestCSIWinnerWritesRejectBeforeReturningEdits(t *testing.T) {
	for _, changes := range [][]CSIWinnerVersionChange{
		{{Version: "1.0.2.0", Installed: true}, {Version: "1.0.2.0", Installed: false}},
		{{Version: "1.0.2.0", Installed: true}, {Version: "2.0.0.0", Installed: true}},
		{{Version: "1.0.2.0", Installed: true}, {Version: "../bad", Installed: true}},
	} {
		plan, err := PlanCSIWinnerWrites([]byte(winnerWriteIdentity), "1.0.1.0", []string{"1.0.1.0"}, changes)
		if err == nil || len(plan.Edits) != 0 || plan.Family != "" {
			t.Fatalf("partial result: %+v %v", plan, err)
		}
	}
}

func applyWinnerEdits(values map[string]map[string]registry.Value, edits []CSIWinnerValueEdit) {
	for _, edit := range edits {
		if edit.Delete {
			delete(values[edit.Branch], edit.Value.Name)
			continue
		}
		if values[edit.Branch] == nil {
			values[edit.Branch] = map[string]registry.Value{}
		}
		value := edit.Value
		value.Name = ""
		values[edit.Branch][edit.Value.Name] = value
	}
}
