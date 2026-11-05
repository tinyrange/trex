package uup

import (
	"reflect"
	"strings"
	"testing"
)

func installMarkFixture(t *testing.T) ([]CSIInstallMarkDeployment, []CBSDeploymentAction) {
	t.Helper()
	id := func(name string) AssemblyIdentity { return compositionFixture(t, name, "").Identity }
	a, b, c, shared, patch, policy, bare := id("A"), id("B"), id("C"), id("Shared"), id("Patch"), id("Policy"), id("Bare")
	policy.Attributes = []ManifestAttribute{{Name: "type", Value: "win32-policy"}}
	bare.Attributes = []ManifestAttribute{{Name: "type", Value: "-policy"}}
	pack := cbsIntentManifest(t, "Package", "neutral", `<update name="u"/>`).Identity
	source := func(update string) []byte {
		data, err := marshalCBSDeploymentSource(cbsDeploymentSource{Package: pack, Update: update}, []byte("opaque secondary"))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	inventory := []CSIInstallMarkDeployment{
		{Identity: a, Composition: []CSICompositionMember{{a, 2}, {shared, 2}, {patch, 1}, {policy, 1}, {bare, 1}}, InstalledSources: [][]byte{source("one"), source("two")}},
		{Identity: b, Composition: []CSICompositionMember{{b, 2}, {shared, 1}}, InstalledSources: [][]byte{source("keep")}},
		{Identity: c, Composition: []CSICompositionMember{{c, 2}, {shared, 1}}},
	}
	actions := []CBSDeploymentAction{
		{Package: pack, UpdateName: "one", Deployment: a, Action: CBSActionUninstall},
		{Package: pack, UpdateName: "new", Deployment: c, Action: CBSActionInstall, Stage: true, Driver: true},
		{Package: pack, UpdateName: "stage-only", Deployment: b, Action: CBSActionNone, Stage: true},
	}
	return inventory, actions
}

func TestCSIInstallMarksCountSourcesNotActiveOwners(t *testing.T) {
	inventory, actions := installMarkFixture(t)
	result, err := AnalyzeCSIInstallMarks(inventory, actions)
	if err != nil {
		t.Fatal(err)
	}
	type counts struct {
		initial, final   uint32
		affected, impact bool
	}
	want := map[string]counts{
		"A": {2, 1, true, true}, "B": {1, 1, false, false}, "C": {0, 1, true, true},
		"Shared": {3, 3, true, true}, "Patch": {2, 1, true, false},
		"Policy": {2, 1, true, true}, "Bare": {2, 1, true, false},
	}
	if len(result) != len(want) {
		t.Fatal(result)
	}
	for _, m := range result {
		if got := (counts{m.Initial, m.Final, m.Affected, m.ImpactfulInstall}); got != want[m.Identity.Name] {
			t.Errorf("%s: %+v want %+v", m.Identity.Name, got, want[m.Identity.Name])
		}
		if m.Identity.Name == "Policy" {
			m.Identity.Attributes[0].Value = "mutated"
		}
	}
	if inventory[0].Composition[3].Identity.Attributes[0].Value != "win32-policy" {
		t.Fatal("result aliases caller identity")
	}
	// Re-running must not consume an input source or mutate a closure.
	again, err := AnalyzeCSIInstallMarks(inventory, actions)
	if err != nil || again[0].Initial != result[0].Initial {
		t.Fatal(again, err)
	}
	// Opposite source transitions commute, even through a shared component.
	actions[0], actions[1] = actions[1], actions[0]
	reversed, err := AnalyzeCSIInstallMarks(inventory, actions)
	if err != nil || !reflect.DeepEqual(again, reversed) {
		t.Fatal(reversed, err)
	}
}

func TestCSIInstallMarksRejectIncompleteOrConflictingSources(t *testing.T) {
	cases := []struct {
		name    string
		edit    func([]CSIInstallMarkDeployment, []CBSDeploymentAction) ([]CSIInstallMarkDeployment, []CBSDeploymentAction)
		message string
	}{
		{"missing owner", func(i []CSIInstallMarkDeployment, a []CBSDeploymentAction) ([]CSIInstallMarkDeployment, []CBSDeploymentAction) {
			return i[1:], a
		}, "missing exact"},
		{"already installed", func(i []CSIInstallMarkDeployment, a []CBSDeploymentAction) ([]CSIInstallMarkDeployment, []CBSDeploymentAction) {
			a[0].Action = CBSActionInstall
			return i, a
		}, "presence"},
		{"absent source", func(i []CSIInstallMarkDeployment, a []CBSDeploymentAction) ([]CSIInstallMarkDeployment, []CBSDeploymentAction) {
			a[0].UpdateName = "not-present"
			return i, a
		}, "presence"},
		{"duplicate action", func(i []CSIInstallMarkDeployment, a []CBSDeploymentAction) ([]CSIInstallMarkDeployment, []CBSDeploymentAction) {
			return i, append(a, a[0])
		}, "duplicate"},
		{"duplicate source", func(i []CSIInstallMarkDeployment, a []CBSDeploymentAction) ([]CSIInstallMarkDeployment, []CBSDeploymentAction) {
			i[0].InstalledSources = append(i[0].InstalledSources, i[0].InstalledSources[0])
			return i, a
		}, "duplicate"},
		{"invalid source", func(i []CSIInstallMarkDeployment, a []CBSDeploymentAction) ([]CSIInstallMarkDeployment, []CBSDeploymentAction) {
			i[0].InstalledSources[0] = []byte("bad")
			return i, a
		}, "source"},
		{"duplicate deployment", func(i []CSIInstallMarkDeployment, a []CBSDeploymentAction) ([]CSIInstallMarkDeployment, []CBSDeploymentAction) {
			return append(i, i[0]), a
		}, "duplicate"},
		{"duplicate member", func(i []CSIInstallMarkDeployment, a []CBSDeploymentAction) ([]CSIInstallMarkDeployment, []CBSDeploymentAction) {
			i[0].Composition = append(i[0].Composition, i[0].Composition[1])
			return i, a
		}, "duplicate"},
		{"missing root", func(i []CSIInstallMarkDeployment, a []CBSDeploymentAction) ([]CSIInstallMarkDeployment, []CBSDeploymentAction) {
			i[0].Composition = i[0].Composition[1:]
			return i, a
		}, "exact root"},
		{"patch root", func(i []CSIInstallMarkDeployment, a []CBSDeploymentAction) ([]CSIInstallMarkDeployment, []CBSDeploymentAction) {
			i[0].Composition[0].Disposition = 1
			return i, a
		}, "root"},
		{"bad disposition", func(i []CSIInstallMarkDeployment, a []CBSDeploymentAction) ([]CSIInstallMarkDeployment, []CBSDeploymentAction) {
			i[0].Composition[1].Disposition = 0
			return i, a
		}, "disposition"},
		{"foreign scope", func(i []CSIInstallMarkDeployment, a []CBSDeploymentAction) ([]CSIInstallMarkDeployment, []CBSDeploymentAction) {
			a[0].Deployment.VersionScope = ""
			return i, a
		}, "missing exact"},
		{"unsupported action", func(i []CSIInstallMarkDeployment, a []CBSDeploymentAction) ([]CSIInstallMarkDeployment, []CBSDeploymentAction) {
			a[0].Action = CBSActionStage
			return i, a
		}, "unsupported"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			i, a := installMarkFixture(t)
			i, a = tc.edit(i, a)
			result, err := AnalyzeCSIInstallMarks(i, a)
			if result != nil || err == nil || !strings.Contains(err.Error(), tc.message) {
				t.Fatalf("%+v %v", result, err)
			}
		})
	}
}
