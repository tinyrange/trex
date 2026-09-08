package x86

import (
	"go.starlark.net/starlark"
	"testing"
)

func TestImportNameQueryBindsClonesIndependently(t *testing.T) {
	m := newRawX86TestMachine(t, starlark.Bytes("\xc3"), nil)
	m.imports[0x2000] = emulatorImport{name: "Run", target: 0x2000}
	query := func(machine *emulatorX86) *starlark.List {
		t.Helper()
		method, err := machine.Attr("imports_named")
		if err != nil {
			t.Fatal(err)
		}
		value, err := starlark.Call(&starlark.Thread{}, method, starlark.Tuple{starlark.Tuple{starlark.String("RUN")}}, nil)
		if err != nil {
			t.Fatal(err)
		}
		return value.(*starlark.List)
	}
	if query(m).Len() != 1 {
		t.Fatal("query missed original import")
	}
	clone := m.clone()
	clone.imports[0x3000] = emulatorImport{name: "run", target: 0x3000}
	if query(clone).Len() != 2 || query(m).Len() != 1 {
		t.Fatal("clone query retained source state")
	}
}
