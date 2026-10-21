package irix

import (
	starfile "github.com/tinyrange/trex/storage/star"
	"strings"
	"testing"
)

func planProducts(version uint32) []Product {
	return []Product{{Name: "main", Images: []ProductImage{{Name: "sw", Version: version, Subsystems: []Subsystem{{Name: "bin", Flags: 2}}}}}}
}
func basicOptions(t *testing.T) PlanOptions {
	f, index := fixture()
	items, err := ReadIDB(index, 100)
	if err != nil {
		t.Fatal(err)
	}
	return PlanOptions{Selected: []string{"main.sw.bin"}, Indexes: map[string][]Item{"main@2": items}, Images: map[string]starfile.File{"main.sw@2": f}, Installed: map[string]uint32{}, Versions: map[string]uint32{}, Machine: map[string]string{}, Existing: map[string]starfile.File{}, Previous: map[string]uint16{}}
}
func TestPlanVersionAndPrerequisiteAlternatives(t *testing.T) {
	p := append(planProducts(1), planProducts(2)...)
	o := basicOptions(t)
	p[1].Images[0].Subsystems[0].Prerequisites = [][]Mark{{{Product: "runtime", Image: "sw", Subsystem: "base", Low: 5, High: 10}, {Product: "extra", Image: "sw", Subsystem: "base", Low: 1, High: 2}}, {{Product: "alternate", Image: "sw", Subsystem: "base", Low: 1, High: 9}}}
	o.Installed["runtime.sw.base"] = 6
	plan, err := Plan(p, o)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Selected[0].Version != 2 || len(plan.Issues) != 1 || plan.Issues[0].Kind != "prerequisite" {
		t.Fatal(plan)
	}
	o.Installed["alternate.sw.base"] = 8
	plan, err = Plan(p, o)
	if err != nil || len(plan.Issues) != 0 {
		t.Fatal(plan, err)
	}
	got, err := starfile.ReadAll(plan.Operations[0].Data)
	if err != nil || string(got) != "A" {
		t.Fatal("not attached to indexed payload", err)
	}
	o.Versions["main.sw.bin"] = 1
	plan, err = Plan(p, o)
	if err != nil || plan.Selected[0].Version != 1 {
		t.Fatal("version pin", err)
	}
	if _, err := Plan(append(p, planProducts(2)...), basicOptions(t)); err == nil {
		t.Fatal("ambiguous descriptor version accepted")
	}
}
func TestMachinePredicates(t *testing.T) {
	attrs := []string{"mach(CPUBOARD=IP12 CPUBOARD=IP22 SUBGR=)"}
	if yes, err := machineMatches(attrs, map[string]string{"CPUBOARD": "IP22", "SUBGR": ""}); err != nil || !yes {
		t.Fatal(yes, err)
	}
	if yes, err := machineMatches(attrs, map[string]string{"CPUBOARD": "IP12", "SUBGR": "MHPI"}); err != nil || yes {
		t.Fatal(yes, err)
	}
	if _, err := machineMatches(attrs, map[string]string{"CPUBOARD": "IP12"}); err == nil {
		t.Fatal("guessed unknown machine fact")
	}
}
func TestPlanConfigurationAndHooks(t *testing.T) {
	for _, policy := range []string{"suggest", "update", "noupdate"} {
		f, index := fixture()
		index.Data = []byte(strings.TrimSpace(string(index.Data)) + " config(" + policy + ") postop(echo 'a (b)' \"c d\")\n")
		items, err := ReadIDB(index, 100)
		if err != nil {
			t.Fatal(err)
		}
		raw := items[0].RawAttributes[len(items[0].RawAttributes)-1]
		if raw != `postop(echo 'a (b)' "c d")` {
			t.Fatalf("action quoting lost: %q", raw)
		}
		o := basicOptions(t)
		o.Indexes["main@2"] = items
		o.Images["main.sw@2"] = f
		o.Existing["/a"] = &starfile.Bytes{Data: []byte("user edited")}
		o.Previous["/a"] = 65
		plan, err := Plan(planProducts(2), o)
		if err != nil {
			t.Fatal(err)
		}
		if len(plan.Hooks) != 1 || plan.Hooks[0].Command != `echo 'a (b)' "c d"` || len(plan.Issues) != 1 || plan.Issues[0].Kind != "install_action" {
			t.Fatalf("hooks: %+v", plan)
		}
		last := plan.Operations[len(plan.Operations)-1]
		switch policy {
		case "suggest":
			if last.Path != "/a.N" {
				t.Fatal(last)
			}
		case "update":
			if len(plan.Operations) != 2 || plan.Operations[0].Path != "/a.O" {
				t.Fatal(plan)
			}
		case "noupdate":
			if last.Kind != "preserve" {
				t.Fatal(last)
			}
		}
	}
}
func TestPlanDoesNotResolveMissingFactsOrUnsafePaths(t *testing.T) {
	o := basicOptions(t)
	o.Indexes["main@2"][0].Attributes = append(o.Indexes["main@2"][0].Attributes, "mach(CPUBOARD=IP12)")
	plan, err := Plan(planProducts(2), o)
	if err != nil || len(plan.Issues) != 1 || plan.Issues[0].Kind != "machine" || len(plan.Operations) != 0 {
		t.Fatal(plan, err)
	}
	o = basicOptions(t)
	o.Indexes["main@2"][0].Path = "../escape"
	if _, err := Plan(planProducts(2), o); err == nil {
		t.Fatal("path traversal accepted")
	}
}
