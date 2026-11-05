package uup

import (
	"reflect"
	"strings"
	"testing"
)

func TestCSIInstallMarksPersistedUnchangedSharedOwner(t *testing.T) {
	inventory, actions := installMarkFixture(t)
	want, err := AnalyzeCSIInstallMarks(inventory, actions)
	if err != nil {
		t.Fatal(err)
	}
	// B shares a component with two changed deployments. Its exact installed
	// source count must contribute without inventing an impact disposition.
	for _, m := range inventory[1].Composition {
		inventory[1].PersistedMembers = append(inventory[1].PersistedMembers, m.Identity)
	}
	inventory[1].Composition = nil
	got, err := AnalyzeCSIInstallMarks(inventory, actions)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("marks differ: %v %v", got, err)
	}
	actions[2].Action = CBSActionInstall
	if _, err := AnalyzeCSIInstallMarks(inventory, actions); err == nil || !strings.Contains(err.Error(), "manifest-derived") {
		t.Fatalf("persisted list authorized change: %v", err)
	}
}

func TestCSIInstallMarksPersistedRejectsIncompleteInventories(t *testing.T) {
	for _, variant := range []string{"both", "duplicate", "missing root", "installed empty"} {
		t.Run(variant, func(t *testing.T) {
			inventory, actions := installMarkFixture(t)
			composition := inventory[1].Composition
			inventory[1].Composition = nil
			inventory[1].PersistedMembers = []AssemblyIdentity{composition[0].Identity, composition[1].Identity}
			switch variant {
			case "both":
				inventory[1].Composition = composition
			case "duplicate":
				inventory[1].PersistedMembers = append(inventory[1].PersistedMembers, composition[1].Identity)
			case "missing root":
				inventory[1].PersistedMembers = inventory[1].PersistedMembers[1:]
			case "installed empty":
				inventory[1].PersistedMembers = []AssemblyIdentity{}
			}
			if _, err := AnalyzeCSIInstallMarks(inventory, actions); err == nil {
				t.Fatal("accepted invalid persisted membership")
			}
		})
	}
	inventory, actions := installMarkFixture(t)
	// Retired unowned canonical keys may persist, but contribute no marks.
	retired := compositionFixture(t, "Retired", "").Identity
	inventory = append(inventory, CSIInstallMarkDeployment{Identity: retired, PersistedMembers: []AssemblyIdentity{}})
	if _, err := AnalyzeCSIInstallMarks(inventory, actions); err != nil {
		t.Fatal(err)
	}
}
