package x86

import (
	"testing"

	"go.starlark.net/starlark"
)

func TestSemanticOverrides(t *testing.T) {
	for _, convention := range []string{"stdcall", "cdecl"} {
		t.Run(convention, func(t *testing.T) {
			machine := newRawX86TestMachine(t, starlark.Bytes("\xc3"), nil)
			thread := &starlark.Thread{Name: "overrides"}
			_, err := starlark.ExecFileOptions(starlarkFileOptions(), thread, "overrides.star", `
def base(event):
    return event.args[0] + 1
def wrapper(event, previous):
    return previous(event) * 2
address = machine.provide_export(base, module="fixture", name="Answer", argc=1, convention=convention)
machine.override(wrapper, module="FIXTURE.DLL", name="answer", wrap=True)
`, starlark.StringDict{"machine": machine, "convention": starlark.String(convention)})
			if err != nil {
				t.Fatal(err)
			}
			address := machine.resolveExport("fixture.dll", "Answer", 0, 0)
			check := func(address uint32, want uint32) {
				t.Helper()
				result, err := machine.callAddress(thread, address, []uint32{20})
				if err != nil {
					t.Fatal(err)
				}
				if got := recordString(t, result.(*starlarkRecord), "reason"); got != "return" {
					t.Fatal(result)
				}
				if got := recordUint32(t, result.(*starlarkRecord), "value"); got != want {
					t.Fatalf("got %d, want %d", got, want)
				}
			}
			check(address, 42)
			checkpoint, err := machine.checkpointBuiltin(nil, nil, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			wrapper := machine.hooks[address].callback
			// The last override wraps the complete previous chain, with no guest re-entry.
			second := starlark.NewBuiltin("outer", func(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
				value, err := starlark.Call(thread, args[1], starlark.Tuple{args[0]}, nil)
				if err != nil {
					return nil, err
				}
				return value.(starlark.Int).Add(starlark.MakeInt(1)), nil
			})
			if _, err := machine.overrideBuiltin(nil, nil, starlark.Tuple{second}, []starlark.Tuple{
				{starlark.String("module"), starlark.String("fixture")},
				{starlark.String("name"), starlark.String("Answer")},
				{starlark.String("wrap"), starlark.True},
			}); err != nil {
				t.Fatal(err)
			}
			check(address, 43)
			machine.applyHookRules(0x2000, emulatorImport{module: "fixture.dll", name: "Answer"})
			check(0x2000, 43)
			if _, err := machine.restoreBuiltin(nil, nil, starlark.Tuple{checkpoint}, nil); err != nil {
				t.Fatal(err)
			}
			check(address, 42)
			if machine.hooks[address].callback != wrapper {
				t.Fatal("checkpoint did not restore callback")
			}
			machine.applyHookRules(0x2000, emulatorImport{module: "fixture.dll", name: "Answer"})
			check(0x2000, 42)
			if hook := machine.hooks[0x2000]; hook.argc != 1 || hook.convention != convention {
				t.Fatal("ABI changed")
			}
		})
	}
}
