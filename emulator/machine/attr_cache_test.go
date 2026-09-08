package machine

import (
	"testing"

	"github.com/tinyrange/trex/emulator/amd64"
	"github.com/tinyrange/trex/emulator/cpu"
	"go.starlark.net/starlark"
)

func TestImportRecordCacheInvalidationAndListOwnership(t *testing.T) {
	m := &Machine{processor: &amd64.CPU{}, memory: cpu.NewAddressSpace(4096)}
	m.addImport(imported{address: 20, name: "second"})
	a, _ := m.Attr("imports")
	b, _ := m.Attr("imports")
	if a.(*starlark.List).Index(0) != b.(*starlark.List).Index(0) {
		t.Fatal("immutable records were rebuilt")
	}
	if err := a.(*starlark.List).SetIndex(0, starlark.None); err != nil {
		t.Fatal(err)
	}
	if b.(*starlark.List).Index(0) == starlark.None {
		t.Fatal("returned lists share mutable storage")
	}
	clone := m.clone()
	query := func(machine *Machine) int {
		t.Helper()
		method, _ := machine.Attr("imports_named")
		value, err := starlark.Call(&starlark.Thread{}, method, starlark.Tuple{starlark.Tuple{starlark.String("FIRST"), starlark.String("SECOND")}}, nil)
		if err != nil {
			t.Fatal(err)
		}
		return value.(*starlark.List).Len()
	}
	if query(m) != 1 || query(clone) != 1 {
		t.Fatal("initial import query failed")
	}
	m.addImport(imported{address: 10, name: "first"})
	if query(m) != 2 || query(clone) != 1 {
		t.Fatal("import query cache invalidation failed")
	}
	c, _ := m.Attr("imports")
	d, _ := clone.Attr("imports")
	if c.(*starlark.List).Len() != 2 || d.(*starlark.List).Len() != 1 {
		t.Fatal("cache invalidation affected snapshot or missed new import")
	}
	name, _ := c.(*starlark.List).Index(0).(starlark.HasAttrs).Attr("name")
	if name != starlark.String("first") {
		t.Fatal("imports are not address sorted")
	}
}

func TestMethodCacheBindsSnapshotsIndependently(t *testing.T) {
	m := &Machine{processor: &amd64.CPU{}, memory: cpu.NewAddressSpace(4096)}
	a, _ := m.Attr("set_register")
	b, _ := m.Attr("set_register")
	if a != b {
		t.Fatal("method was rebound")
	}
	clone := m.clone()
	method, _ := clone.Attr("set_register")
	if method == a {
		t.Fatal("clone retained original method")
	}
	_, err := starlark.Call(&starlark.Thread{}, method, starlark.Tuple{starlark.String("rax"), starlark.MakeInt(42)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	x, _ := m.processor.Register("rax")
	y, _ := clone.processor.Register("rax")
	if x != 0 || y != 42 {
		t.Fatalf("original=%d clone=%d", x, y)
	}
}
