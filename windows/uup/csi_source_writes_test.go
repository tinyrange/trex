package uup

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/tinyrange/trex/windows/registry"
)

func sourceWriteFixture(t *testing.T, update, secondary string) registry.Value {
	t.Helper()
	pack := cbsIntentManifest(t, "Package", "neutral", `<update name="u"/>`).Identity
	data, err := marshalCBSDeploymentSource(cbsDeploymentSource{Package: pack, Update: update}, []byte(secondary))
	if err != nil {
		t.Fatal(err)
	}
	source, err := ParseCBSDeploymentSource(data)
	if err != nil {
		t.Fatal(err)
	}
	return registry.Value{Name: "p!" + source.SourceKey, Type: 3, Data: data}
}

func TestCSISourceWritesPreserveOpaqueExistingData(t *testing.T) {
	old := sourceWriteFixture(t, "one", "opaque resident secondary")
	replacement := sourceWriteFixture(t, "one", "8")
	sibling := sourceWriteFixture(t, "two", "2")
	installed := old
	installed.Name = "i!" + old.Name[2:]
	before := []registry.Value{old, installed, sibling}
	changes := []CSISourceChange{
		{Kind: 1, Data: replacement.Data}, // Existing pin is NOT rewritten.
		{Kind: 4, Data: replacement.Data}, // A new staged mark has its own bytes.
		{Kind: 2, Delete: true, Data: replacement.Data},
	}
	plan, err := PlanCSISourceWrites(before, changes)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Before != (CSISourceCounts{Pinned: 2, Installed: 1}) || plan.After != (CSISourceCounts{Pinned: 2, Staged: 1}) {
		t.Fatal(plan)
	}
	if len(plan.Edits) != 2 {
		t.Fatal(plan.Edits)
	}
	state := map[string]registry.Value{}
	for _, v := range before {
		state[strings.ToLower(v.Name)] = v
	}
	// Unrelated deployment metadata must survive applying source-only edits.
	state["appid"] = registry.Value{Name: "appid", Type: 3, Data: []byte("identity")}
	for _, edit := range plan.Edits {
		if edit.Delete {
			delete(state, strings.ToLower(edit.Value.Name))
		} else {
			state[strings.ToLower(edit.Value.Name)] = edit.Value
		}
	}
	if !bytes.Equal(state[strings.ToLower(old.Name)].Data, old.Data) || !bytes.Equal(state[strings.ToLower(sibling.Name)].Data, sibling.Data) {
		t.Fatal("resident payload changed")
	}
	if _, ok := state[strings.ToLower(installed.Name)]; ok {
		t.Fatal("installed source not removed")
	}
	staged := state[strings.ToLower("s!"+old.Name[2:])]
	if staged.Type != 3 || !bytes.Equal(staged.Data, replacement.Data) || len(state) != 4 {
		t.Fatal(state)
	}
	replacement.Data[0] ^= 0xff
	if bytes.Equal(staged.Data, replacement.Data) {
		t.Fatal("planned payload aliases input")
	}
}

func TestCSISourceWritesOrderedReplaceAndIndependentKinds(t *testing.T) {
	old := sourceWriteFixture(t, "one", "old")
	next := sourceWriteFixture(t, "one", "128")
	// Registry value lookup is case insensitive; deletion retains original name.
	old.Name = strings.ToUpper(old.Name)
	plan, err := PlanCSISourceWrites([]registry.Value{old}, []CSISourceChange{
		{Kind: 1, Delete: true, Data: next.Data}, {Kind: 1, Data: next.Data},
		{Kind: 2, Data: next.Data}, {Kind: 2, Data: next.Data},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Edits) != 3 || !plan.Edits[0].Delete || plan.Edits[0].Value.Name != old.Name || plan.Edits[1].Delete || !bytes.Equal(plan.Edits[1].Value.Data, next.Data) {
		t.Fatal(plan)
	}
	if plan.After != (CSISourceCounts{Pinned: 1, Installed: 1}) {
		t.Fatal(plan.After)
	}
	if !bytes.Equal(old.Data, sourceWriteFixture(t, "one", "old").Data) {
		t.Fatal("baseline mutated")
	}
}

func TestCSISourceWritesFailAtomically(t *testing.T) {
	old := sourceWriteFixture(t, "one", "old")
	next := sourceWriteFixture(t, "two", "8")
	tests := []struct {
		name    string
		before  []registry.Value
		changes []CSISourceChange
	}{
		{"duplicate baseline", []registry.Value{old, old}, nil},
		{"name mismatch", []registry.Value{{Name: next.Name, Type: 3, Data: old.Data}}, nil},
		{"wrong type", []registry.Value{{Name: old.Name, Type: 1, Data: old.Data}}, nil},
		{"non-source", []registry.Value{{Name: "appid", Type: 3, Data: old.Data}}, nil},
		{"non-CBS", []registry.Value{{Name: "p!other", Type: 3, Data: old.Data}}, nil},
		{"bad payload", nil, []CSISourceChange{{Kind: 1, Data: []byte{0}}}},
		{"combined mask", nil, []CSISourceChange{{Kind: 3, Data: old.Data}}},
		{"absent delete after valid add", nil, []CSISourceChange{{Kind: 1, Data: old.Data}, {Kind: 2, Delete: true, Data: old.Data}}},
		{"double delete", []registry.Value{old}, []CSISourceChange{{Kind: 1, Delete: true, Data: old.Data}, {Kind: 1, Delete: true, Data: old.Data}}},
		{"late bad payload", []registry.Value{old}, []CSISourceChange{{Kind: 1, Delete: true, Data: old.Data}, {Kind: 4, Data: []byte{0}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plan, err := PlanCSISourceWrites(tt.before, tt.changes)
			if err == nil || !reflect.DeepEqual(plan, CSISourceWritePlan{}) {
				t.Fatalf("partial plan or accepted invalid input: %+v %v", plan, err)
			}
		})
	}
}
