package x86

import (
	"go.starlark.net/starlark"
	"golang.org/x/arch/x86/x86asm"
	"testing"
)

func TestStoppedIndirectAPICallCanResume(t *testing.T) {
	for _, tail := range []bool{false, true} {
		code := []byte{0xb8, 0x00, 0x20, 0, 0, 0xff, 0xd0, 0xc3}
		if tail {
			code[6] = 0xe0
		}
		m := newRawX86TestMachine(t, starlark.Bytes(code), nil)
		calls := 0
		callback := starlark.NewBuiltin("wait", func(_ *starlark.Thread, _ *starlark.Builtin, _ starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
			calls++
			if calls == 1 {
				m.pendingStop = "wait"
			}
			return starlark.MakeInt(42), nil
		})
		m.hooks[0x2000] = emulatorHook{address: 0x2000, callback: callback, convention: "stdcall"}
		th := &starlark.Thread{Name: "resume"}
		r, err := m.callAddress(th, 0x1000, nil)
		if err != nil {
			t.Fatal(err)
		}
		if recordString(t, r.(*starlarkRecord), "reason") != "wait" || m.registers[x86asm.EAX] != 42 || m.eip != 0x1005 {
			t.Fatalf("tail=%v stopped state: %v eax=%x eip=%x", tail, r, m.registers[x86asm.EAX], m.eip)
		}
		context, err := m.captureContext()
		if err != nil {
			t.Fatal(err)
		}
		m.pendingBranch = nil
		if err := m.restoreContext(context); err != nil {
			t.Fatal(err)
		}
		r, err = m.run(th)
		if err != nil {
			t.Fatal(err)
		}
		if recordString(t, r.(*starlarkRecord), "reason") != "return" || recordUint32(t, r.(*starlarkRecord), "value") != 42 || calls != 2 {
			t.Fatalf("tail=%v resume: %v calls=%d", tail, r, calls)
		}
	}
}

func TestUnhandledImportCanResumeAfterBinding(t *testing.T) {
	for _, tail := range []bool{false, true} {
		code := []byte{0xb8, 0x00, 0x20, 0, 0, 0xff, 0xd0, 0xc3}
		if tail {
			code[6] = 0xe0
		}
		m := newRawX86TestMachine(t, starlark.Bytes(code), nil)
		m.imports[0x2000] = emulatorImport{module: "fixture.dll", name: "LateBound", target: 0x2000}
		th := &starlark.Thread{Name: "late-bound"}
		r, err := m.callAddress(th, 0x1000, nil)
		if err != nil {
			t.Fatal(err)
		}
		if recordString(t, r.(*starlarkRecord), "reason") != "plugin" || m.eip != 0x1005 {
			t.Fatalf("tail=%v stop %v", tail, r)
		}
		callback := starlark.NewBuiltin("bound", func(_ *starlark.Thread, _ *starlark.Builtin, _ starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
			return starlark.MakeInt(42), nil
		})
		m.hooks[0x2000] = emulatorHook{address: 0x2000, callback: callback, convention: "stdcall"}
		r, err = m.run(th)
		if err != nil {
			t.Fatal(err)
		}
		if recordString(t, r.(*starlarkRecord), "reason") != "return" || recordUint32(t, r.(*starlarkRecord), "value") != 42 {
			t.Fatalf("tail=%v resume %v", tail, r)
		}
	}
}
