package uup

import (
	"fmt"
	"reflect"
	"testing"
)

func deploymentActionPopulation(t *testing.T) *CBSOrdinaryPopulation {
	t.Helper()
	ref := func(kind string) string {
		declaration := kind
		if kind == "driver" {
			declaration += ` inf="declared.inf" ranking="normal" bootCritical="true"`
		}
		return fmt.Sprintf(`<%s><assemblyIdentity name="Payload" version="10.0.1.2" publicKeyToken="31bf3856ad364e35" processorArchitecture="amd64" language="neutral" versionScope="nonSxS" type="win32"/></%s>`, declaration, kind)
	}
	staged := `<selectable disposition="staged"><detectNone default="false"/></selectable>`
	m := cbsIntentManifest(t, "Root", "neutral",
		`<update name="Install">`+ref("component")+`</update>`+
			`<update name="Stage">`+staged+ref("component")+`</update>`+
			`<update name="Keep">`+ref("component")+`</update>`+
			`<update name="Remove">`+staged+ref("driver")+`</update>`+
			`<update name="ExistingStage">`+staged+ref("component")+`</update>`+
			`<update name="Feature"/>`)
	unadmitted := cbsIntentManifest(t, "Unadmitted", "neutral", `<update name="u">`+ref("component")+`</update>`)
	index, err := NewCBSUpdateStateIndex([]CBSPackageIntent{{Manifest: m, IntendedState: 0x70}, {Manifest: unadmitted, IntendedState: 0x70}})
	if err != nil {
		t.Fatal(err)
	}
	policy := populationPolicy()
	policy.Watch = ordinaryWatchPolicy()
	policy.Watch.InitialUpdate = func(_ AssemblyIdentity, u string, _ uint32, _ *CBSUpdateStateIndex) (CBSOrdinaryUpdateStart, error) {
		return CBSOrdinaryUpdateStart{State: map[string]uint32{"Install": 0, "Stage": 0, "Keep": 0x70, "Remove": 0x70, "ExistingStage": 0x40, "Feature": 0x70}[u], HasDeployments: u != "Feature"}, nil
	}
	root := populationRequest(t, m, 0x70)
	p, err := PlanCBSOrdinaryPopulation(index, nil, []CBSOrdinaryRequest{root, root}, policy)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Executions) != 1 || p.Executions[0].Action != CBSActionNone {
		t.Fatalf("expected merged no-action package: %+v", p.Executions)
	}
	return p
}

func TestCBSDeploymentActionsSeparateStageAndExecute(t *testing.T) {
	p := deploymentActionPopulation(t)
	actions, err := PlanCBSDeploymentActions(p)
	if err != nil {
		t.Fatal(err)
	}
	type summary struct {
		name          string
		stage, driver bool
		action        CBSExecutionAction
	}
	var got []summary
	for _, a := range actions {
		got = append(got, summary{a.UpdateName, a.Stage, a.Driver, a.Action})
	}
	want := []summary{{"Install", true, false, CBSActionInstall}, {"Stage", true, false, CBSActionNone}, {"Keep", false, false, CBSActionNone}, {"Remove", false, true, CBSActionUninstall}, {"ExistingStage", false, false, CBSActionNone}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%+v, want %+v", got, want)
	}
	// Superseded is a staged source, never permanent/installed. Neither case
	// should manufacture another staging pass or an install action.
	p.Executions[0].UpdateStarts["existingstage"] = CBSOrdinaryUpdateStart{State: 0x50, HasDeployments: true}
	p.Executions[0].Updates["existingstage"] = 0x50
	again, err := PlanCBSDeploymentActions(p)
	if err != nil || again[4].Stage || again[4].Action != CBSActionNone {
		t.Fatal(again, err)
	}
	// Completed staged removal can retain the manifest pin while its payload
	// is no longer staged. An unchanged Resolved source needs no stage/install
	// or unresolve operation; it must not be mistaken for an absent source.
	p.Executions[0].UpdateStarts["existingstage"] = CBSOrdinaryUpdateStart{State: 0x20, HasDeployments: true}
	p.Executions[0].Updates["existingstage"] = 0x20
	again, err = PlanCBSDeploymentActions(p)
	if err != nil || again[4].Stage || again[4].Action != CBSActionNone {
		t.Fatal(again, err)
	}
	// Resolved -> Staged requires payload staging but no execute action;
	// Resolved -> Installed additionally requires installation.
	p.Executions[0].Updates["existingstage"] = 0x40
	again, err = PlanCBSDeploymentActions(p)
	if err != nil || !again[4].Stage || again[4].Action != CBSActionNone {
		t.Fatal(again, err)
	}
	p.Executions[0].Updates["existingstage"] = 0x70
	again, err = PlanCBSDeploymentActions(p)
	if err != nil || !again[4].Stage || again[4].Action != CBSActionInstall {
		t.Fatal(again, err)
	}
	if len(actions[3].DriverAttributes) != 3 || actions[3].DriverAttributes[0].Value != "declared.inf" {
		t.Fatal("driver declaration was not retained", actions[3])
	}
	for i, a := range actions {
		if i != 3 && len(a.DriverAttributes) != 0 {
			t.Fatal("driver metadata leaked to component", a)
		}
	}
	// Results own their driver and identity slices, independent of the snapshot.
	actions[3].DriverAttributes[0].Value = "mutated"
	freshDriver, err := PlanCBSDeploymentActions(p)
	if err != nil || freshDriver[3].DriverAttributes[0].Value == "mutated" {
		t.Fatal(freshDriver, err)
	}
	// Results own their identity attribute slices, independent of the snapshot.
	actions[0].Deployment.Attributes[0].Value = "mutated"
	fresh, err := PlanCBSDeploymentActions(p)
	if err != nil || fresh[0].Deployment.Attributes[0].Value == "mutated" {
		t.Fatal(fresh, err)
	}
}

func TestCBSDeploymentActionsFailClosed(t *testing.T) {
	cases := map[string]func(*CBSOrdinaryPopulation){
		"missing-start":   func(p *CBSOrdinaryPopulation) { delete(p.Executions[0].UpdateStarts, "stage") },
		"missing-target":  func(p *CBSOrdinaryPopulation) { delete(p.Executions[0].Updates, "stage") },
		"deployment-free": func(p *CBSOrdinaryPopulation) { p.Executions[0].UpdateStarts["stage"] = CBSOrdinaryUpdateStart{} },
		"unresolve": func(p *CBSOrdinaryPopulation) {
			p.Executions[0].UpdateStarts["stage"] = CBSOrdinaryUpdateStart{State: 0x20, HasDeployments: true}
			p.Executions[0].Updates["stage"] = 0
		},
		"unstage":           func(p *CBSOrdinaryPopulation) { p.Executions[0].Updates["keep"] = 0 },
		"pending":           func(p *CBSOrdinaryPopulation) { p.Executions[0].Updates["stage"] = 0x30 },
		"undrained":         func(p *CBSOrdinaryPopulation) { p.Executions[0].DirtyUpdates["stage"] = true },
		"stale-package":     func(p *CBSOrdinaryPopulation) { p.Executions[0].IntendedState = 0x40 },
		"duplicate-package": func(p *CBSOrdinaryPopulation) { p.Executions = append(p.Executions, p.Executions[0]) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := deploymentActionPopulation(t)
			mutate(p)
			if result, err := PlanCBSDeploymentActions(p); err == nil || result != nil {
				t.Fatal(result, err)
			}
		})
	}
	if result, err := PlanCBSDeploymentActions(nil); err == nil || result != nil {
		t.Fatal(result, err)
	}
}
