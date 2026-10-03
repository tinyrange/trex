package starlarkfrontend

import (
	"testing"

	"go.starlark.net/starlark"
)

func TestNestedInstallerLocationsPreserveCallerPolicy(t *testing.T) {
	thread, _, err := newStarlarkRuntime("-")
	if err != nil {
		t.Fatal(err)
	}
	module, err := thread.Load(thread, "@stdlib//windows:installer.star")
	if err != nil {
		t.Fatal(err)
	}
	component := func(name string) starlark.Value {
		dict := starlark.NewDict(2)
		_ = dict.SetKey(starlark.String("name"), starlark.String(name))
		_ = dict.SetKey(starlark.String("groups"), starlark.NewList([]starlark.Value{starlark.String("payload")}))
		return dict
	}
	nested := namespace{attrs: starlark.StringDict{
		"format": starlark.String("installshield5"),
		"payload": namespace{attrs: starlark.StringDict{"components": starlark.NewList([]starlark.Value{
			component("English/Sites"), component("English/FireScripts"), component("English/PreInstall"),
		})}},
		"plan": starlark.NewBuiltin("plan", func(_ *starlark.Thread, _ *starlark.Builtin, _ starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
			write := starlark.NewDict(3)
			for key, value := range map[string]string{"operation": "set_value", "name": "DataDir", "data": `C:\User Data`} {
				_ = write.SetKey(starlark.String(key), starlark.String(value))
			}
			plan := starlark.NewDict(1)
			_ = plan.SetKey(starlark.String("definitive_registry_writes"), starlark.NewList([]starlark.Value{write}))
			return plan, nil
		}),
	}}
	inherited := starlark.NewDict(2)
	_ = inherited.SetKey(starlark.String("<WINSYSDIR>"), starlark.String(`C:\WINDOWS\SYSTEM`))
	_ = inherited.SetKey(starlark.String("english/sites"), starlark.String(`C:\Chosen Sites`))
	_ = inherited.SetKey(starlark.String("English/FireScripts"), starlark.String(`C:\Application`))
	explicit := starlark.NewDict(1)
	_ = explicit.SetKey(starlark.String("english/sites"), starlark.String(`C:\Chosen Sites`))
	result, err := starlark.Call(thread, module["_nested_installer_locations"].(starlark.Callable), starlark.Tuple{
		nested, inherited, starlark.String(`C:\Application`), explicit,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	locations := result.(*starlark.Dict)
	for name, want := range map[string]string{
		"english/sites":       `C:\Chosen Sites`,
		"English/FireScripts": `C:\User Data\FireScripts`,
		"English/PreInstall":  `C:\Application`,
	} {
		got, found, err := locations.Get(starlark.String(name))
		if err != nil || !found || got != starlark.String(want) {
			t.Errorf("location %q = %v (found %t, error %v), want %q", name, got, found, err, want)
		}
	}
	if _, found, _ := locations.Get(starlark.String("English/Sites")); found {
		t.Error("defaults introduced a second case variant of the caller's component")
	}
	if inherited.Len() != 3 {
		t.Error("nested defaults mutated caller locations")
	}
}
