package windows

import (
	"testing"

	"go.starlark.net/starlark"
)

func TestCBSUpdateIndexBuiltinIsolationAndBounds(t *testing.T) {
	source := `
name = "Parent~31bf3856ad364e35~amd64~~10.0.26100.1"
manifest = b'<assembly xmlns="urn:schemas-microsoft-com:asm.v3"><assemblyIdentity name="Parent" version="10.0.26100.1" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral"/><package><update name="feature"/></package></assembly>'
inputs = [dict(manifest=manifest, intended_state=0)]
old = make_index(inputs)
old_value = old.state(name, "feature")
next = old.with_states({name: 112})
new_value = next.state(name, "FEATURE")
inputs[0]["intended_state"] = 64
old_again = old.state(name, "feature")
published = next.with_updates(name, {"FEATURE": 64})
published_value = published.state(name, "feature")
direct_value = published.applicable(name, "feature")
cleared_value = published.with_updates(name, {"feature": 4096}).state(name, "feature")
`
	globals, err := starlark.ExecFile(&starlark.Thread{Name: t.Name()}, "snapshot.star", source, starlark.StringDict{"make_index": starlark.NewBuiltin("cbs_update_index", cbsUpdateIndexBuiltin)})
	if err != nil {
		t.Fatal(err)
	}
	attr := func(v starlark.Value, key string) starlark.Value {
		t.Helper()
		got, err := v.(starlark.HasAttrs).Attr(key)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	for name, want := range map[string]string{"old_value": "0", "old_again": "0", "new_value": "112", "direct_value": "112", "cleared_value": "112"} {
		if got := attr(globals[name], "intended_state").String(); got != want {
			t.Fatal(name, got, want)
		}
		if got := attr(globals[name], "raw_state").String(); got != "112" {
			t.Fatal("lost raw state", name, got)
		}
	}
	if got := attr(globals["published_value"], "raw_state").String(); got != "64" {
		t.Fatal("ignored explicit published target", got)
	}
	if got := attr(globals["published_value"], "intended_state").String(); got != "64" {
		t.Fatal("lost published target", got)
	}
	withUpdates := attr(globals["published"], "with_updates").(starlark.Callable)
	duplicate := starlark.NewDict(2)
	_ = duplicate.SetKey(starlark.String("FEATURE"), starlark.MakeInt(64))
	_ = duplicate.SetKey(starlark.String("feature"), starlark.MakeInt(112))
	if _, err := starlark.Call(&starlark.Thread{}, withUpdates, starlark.Tuple{globals["name"], duplicate}, nil); err == nil {
		t.Fatal("accepted case-duplicate published targets")
	}
	withStates := attr(globals["old"], "with_states").(starlark.Callable)
	for _, bad := range []starlark.Value{starlark.MakeInt(-1), starlark.MakeInt(0x60), starlark.MakeInt(0x1000), starlark.MakeUint64(1<<32 | 0x70), starlark.True} {
		changes := starlark.NewDict(1)
		_ = changes.SetKey(globals["name"], bad)
		if _, err := starlark.Call(&starlark.Thread{}, withStates, starlark.Tuple{changes}, nil); err == nil {
			t.Fatal("accepted invalid state", bad)
		}
	}
	// Read-only query support for absent packages must not authorize zero owner writes.
	targets := starlark.NewList([]starlark.Value{globals["name"]})
	input := starlark.NewDict(2)
	if err := input.SetKey(starlark.String("manifest"), globals["manifest"]); err != nil {
		t.Fatal(err)
	}
	if err := input.SetKey(starlark.String("intended_state"), starlark.MakeInt(0)); err != nil {
		t.Fatal(err)
	}
	packages := starlark.NewList([]starlark.Value{input})
	if _, err := cbsPackageOwnersBuiltin(nil, nil, starlark.Tuple{packages, targets}, nil); err == nil {
		t.Fatal("read-only decoder relaxed owner policy")
	}
}
