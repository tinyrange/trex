package lab

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tinyrange/trex/vmm/ethernet"
)

type observedGuest struct{}

func (*observedGuest) Close() error        { return nil }
func (*observedGuest) Surfaces() []Surface { return nil }

type observedFactory struct {
	mu     sync.Mutex
	starts []StartRequest
	guests []*observedGuest
	failID string
}

func (f *observedFactory) Start(_ context.Context, req StartRequest) (Guest, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.starts = append(f.starts, req)
	if req.Node.ID == f.failID {
		return nil, errors.New("injected guest startup failure")
	}
	guest := new(observedGuest)
	f.guests = append(f.guests, guest)
	return guest, nil
}

func waitState(t *testing.T, m *Manager, want string) View {
	t.Helper()
	deadline := time.After(3 * time.Second)
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		view := m.View()
		if view.State == want {
			return view
		}
		select {
		case <-deadline:
			t.Fatalf("state %s, want %s: %s", view.State, want, view.Error)
		case <-tick.C:
		}
	}
}

func domainFixture() ([]Recipe, Definition) {
	recipes := append(Catalog(),
		Recipe{ID: "server", ProvidesDomain: true, LegacyController: "old-server", Ports: []Port{ethernetPort},
			Fields: []Field{{Key: "role", Kind: "select", Options: []Option{{"domain-controller", "Domain controller"}}}}},
		Recipe{ID: "member", DomainController: "server", Ports: []Port{ethernetPort},
			Fields: []Field{{Key: "domain", Kind: "string"}}},
	)
	definition := Blank()
	definition.Nodes = []Node{
		{ID: "switch", Name: "Switch", Recipe: "switch"},
		{ID: "controller", Name: "Controller", Recipe: "server", Config: map[string]any{"role": "domain-controller"}},
		{ID: "workstation", Name: "Workstation", Recipe: "member", Config: map[string]any{"domain": "controller"}},
	}
	definition.Links = []Link{{End{"switch", "port1"}, End{"controller", "lan"}}, {End{"switch", "port2"}, End{"workstation", "lan"}}}
	return recipes, definition
}

func softwareFixture() Recipe {
	return Recipe{ID: "desktop", Fields: []Field{{Key: "software", Kind: "packages", Label: "Applications", Impact: "rebuild", Default: []string{},
		Options: []Option{{"editor", "Editor"}, {"sheets", "Sheets"}}}}, Media: []Media{
		{Key: "system", Kind: "file"},
		{Key: "app-editor", Kind: "file", When: "software", Equals: "editor"},
		{Key: "app-sheets", Kind: "file", When: "software", Equals: "sheets"},
	}}
}

func TestApplyDomainMemberPreservesController(t *testing.T) {
	f := &observedFactory{}
	recipes, d := domainFixture()
	m := NewManager(t.Context(), Blank(), recipes, f, nil, nil)
	t.Cleanup(m.Shutdown)
	if _, err := m.Apply(d); err != nil {
		t.Fatal(err)
	}
	waitState(t, m, "running")

	d.Nodes = append(d.Nodes, Node{ID: "second", Name: "Second member", Recipe: "member", Config: map[string]any{"domain": "controller"}})
	d.Links = append(d.Links, Link{End{"second", "lan"}, End{"switch", "lan"}})
	p := m.Plan(d)
	if len(p.Issues) != 0 || len(p.Changes) != 1 || p.Changes[0].Node != "second" || p.Changes[0].Action != "start" {
		t.Fatalf("adding a member must leave the controller in place: %+v", p)
	}

	f.mu.Lock()
	f.failID = "second"
	f.mu.Unlock()
	if _, err := m.Apply(d); err != nil {
		t.Fatal(err)
	}
	failed := waitState(t, m, "failed")
	if _, running := failed.Applied.Node("second"); running || failed.Nodes["controller"].Phase != "running" {
		t.Fatalf("partial failure lost the running graph: %+v", failed)
	}

	f.mu.Lock()
	f.failID = ""
	f.mu.Unlock()
	if _, err := m.Apply(d); err != nil {
		t.Fatal(err)
	}
	waitState(t, m, "running")
	f.mu.Lock()
	starts := append([]StartRequest(nil), f.starts...)
	f.mu.Unlock()
	if len(starts) != 4 {
		t.Fatalf("controller or another node restarted: %d calls", len(starts))
	}
	var network *ethernet.Switch = starts[0].Switch
	controller := starts[1].Domain
	if network == nil || controller == nil {
		t.Fatal("the declared domain and Ethernet connections did not resolve")
	}
	for _, start := range starts[1:] {
		if start.Domain != controller || start.Switch != network {
			t.Fatal("the live domain or Ethernet link changed during apply")
		}
	}

	m.Stop()
	stopped := waitState(t, m, "idle")
	if stopped.Applied != nil || len(stopped.Definition.Nodes) != 4 {
		t.Fatal("stopping should release guests and keep the editable definition")
	}
}

func TestValidateActiveMediaAndNetwork(t *testing.T) {
	catalog := make(map[string]Recipe)
	recipes, topology := domainFixture()
	for _, r := range recipes {
		catalog[r.ID] = r
	}
	software := softwareFixture()
	catalog[software.ID] = software
	d := Blank()
	d.Nodes = []Node{{ID: "pc", Name: "Desktop", Recipe: "desktop", Config: map[string]any{"software": "editor"},
		Media: map[string]string{"system": "Original/install.iso"}}}
	checked := []string{}
	issues := Validate(d, catalog, func(_ Recipe, slot Media, ref string) error {
		checked = append(checked, ref)
		return nil
	})
	if len(checked) != 1 || len(issues) != 1 || issues[0].Field != "app-editor" {
		t.Fatalf("conditional media was not planned: %+v", issues)
	}
	d = topology
	d.Links = d.Links[:1]
	issues = Validate(d, catalog, nil)
	if len(issues) != 1 || !strings.Contains(issues[0].Message, "same isolated switch") {
		t.Fatalf("expected an unattached member issue, got %+v", issues)
	}
}

func TestPlanResolvesMediaDefaultsAndOverrides(t *testing.T) {
	recipe := Recipe{ID: "guest", Media: []Media{{Key: "system", Default: "Library/install.iso"}}}
	recipes := map[string]Recipe{recipe.ID: recipe}
	definition := Blank()
	definition.Nodes = []Node{{ID: "guest", Name: "Guest", Recipe: recipe.ID}}
	var checked string
	check := func(_ Recipe, _ Media, ref string) error { checked = ref; return nil }
	if plan := Diff(definition, Blank(), recipes, check); len(plan.Issues) != 0 || checked != "Library/install.iso" {
		t.Fatalf("default media checked = %q, plan = %+v", checked, plan)
	}
	actual := definition.Clone()
	definition.Nodes[0].Media = map[string]string{"system": "Library/install.iso"}
	if plan := Diff(definition, actual, recipes, check); len(plan.Changes) != 0 || len(plan.Issues) != 0 {
		t.Fatalf("equivalent override triggered a change: %+v", plan)
	}
	definition.Nodes[0].Media["system"] = "Library/other.iso"
	plan := Diff(definition, actual, recipes, check)
	if checked != "Library/other.iso" || len(plan.Changes) != 1 || plan.Changes[0].Action != "rebuild" {
		t.Fatalf("overridden media checked = %q, plan = %+v", checked, plan)
	}
}

func TestNumberedSwitchPortsPreserveConnections(t *testing.T) {
	catalog := make(map[string]Recipe)
	recipes, legacy := domainFixture()
	for _, r := range recipes {
		catalog[r.ID] = r
	}
	legacy.Nodes[1].Recipe = "old-server"
	delete(legacy.Nodes[1].Config, "role")
	legacy.Links[0].A.Port = "lan"
	migrated := legacy.normalized(catalog)
	if migrated.Nodes[1].Recipe != "server" || migrated.Nodes[1].Config["role"] != "domain-controller" {
		t.Fatalf("domain alias did not migrate: %+v", migrated.Nodes[1])
	}
	if migrated.Links[0].A.Port != "port1" || migrated.Links[1].A.Port != "port2" || len(Validate(migrated, catalog, nil)) != 0 {
		t.Fatalf("old shared port failed to migrate: %+v", migrated.Links)
	}
	moved := migrated.Clone()
	moved.Links[0].A.Port = "port3"
	plan := Diff(moved, migrated, catalog, nil)
	if len(plan.Issues) != 0 || len(plan.Changes) != 1 || plan.Changes[0].Action != "layout" {
		t.Fatalf("moving a cable on the same switch should preserve the running machine: %+v", plan)
	}
	moved.Links[0].A.Port = "port2"
	if issues := Validate(moved, catalog, nil); len(issues) != 1 || issues[0].Node != "switch" {
		t.Fatalf("expected an issue for the occupied switch port: %+v", issues)
	}
}

func TestMultipleSoftwarePackagesAndLegacySelection(t *testing.T) {
	fixture := softwareFixture()
	recipes := map[string]Recipe{fixture.ID: fixture}
	node := Node{ID: "win", Name: "Windows", Recipe: "desktop", Config: map[string]any{"software": "editor"}}
	old := Blank()
	old.Nodes = append(old.Nodes, node)
	draft := old.normalized(recipes)
	if plan := Diff(draft, old, recipes, nil); len(plan.Issues) != 0 || len(plan.Changes) != 0 {
		t.Fatalf("migrating the legacy choice changed the plan: %+v", plan)
	}
	draft.Nodes[0].Config["software"] = []any{"editor", "sheets"}
	if plan := Diff(draft, old, recipes, nil); len(plan.Issues) != 0 || len(plan.Changes) != 1 || plan.Changes[0].Action != "rebuild" {
		t.Fatalf("adding an application must rebuild the guest: %+v", plan)
	}
	var active []string
	for _, slot := range recipes["desktop"].Media {
		if slot.When == "software" && slot.Active(draft.Nodes[0], recipes["desktop"]) {
			active = append(active, slot.Key)
		}
	}
	if len(active) != 2 {
		t.Fatalf("both installers must be selected: %v", active)
	}
	draft.Nodes[0].Config["software"] = []any{"editor", true}
	if issues := Validate(draft, recipes, nil); len(issues) != 1 || issues[0].Field != "software" {
		t.Fatalf("expected an invalid software selection issue: %+v", issues)
	}
}
