package cc

import (
	"go.starlark.net/starlark"
	"testing"
)

func TestBackendDevicesPreservePositionalOptions(t *testing.T) {
	value, err := starlark.Call(&starlark.Thread{Name: "backend-compat"}, Builtins()["backend"], starlark.Tuple{starlark.True}, nil)
	if err != nil {
		t.Fatal(err)
	}
	b := value.(*Backend)
	if !b.ACPI || len(b.Devices) != 0 {
		t.Fatal("new attachment option displaced existing positional ACPI argument")
	}
}
