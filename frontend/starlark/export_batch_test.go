package starlarkfrontend

import (
	"go.starlark.net/starlark"
	"testing"
)

const exportBatchScript = `
def callback(event):
    return event.args[0] + event.args[1]
def exercise(architecture, batch, count):
    machine = emulator.machine(architecture=architecture, code=b"\xc3")
    signatures = {"Function%d" % i: 2 for i in range(count)}
    if batch:
        addresses = machine.provide_exports(callback, module="example.dll", signatures=signatures)
    else:
        addresses = [machine.provide_export(callback, module="example.dll", name=name, argc=argc) for name, argc in signatures.items()]
    return machine, addresses
def check():
    for architecture in ["x86", "amd64"]:
        single, expected = exercise(architecture, False, 3)
        batched, actual = exercise(architecture, True, 3)
        if expected != actual:
            fail("batch changed export ordering or addresses")
        for i in range(3):
            if batched.resolve_export("example.dll", name="Function%d" % i) != actual[i]:
                fail("batch export was not published")
            result = batched.call(actual[i], args=[10, i])
            if result.reason != "return" or result.value != 10+i:
                fail("batch callback arguments or result changed")
check()
`

func TestExportBatchAcrossArchitectures(t *testing.T) {
	architectureScript(t, exportBatchScript)
}

func BenchmarkExportBatch(b *testing.B) {
	thread, predeclared, err := newStarlarkRuntime("-")
	if err != nil {
		b.Fatal(err)
	}
	globals, err := starlark.ExecFile(thread, "export-batch.star", exportBatchScript, predeclared)
	if err != nil {
		b.Fatal(err)
	}
	for _, architecture := range []string{"x86", "amd64"} {
		for _, batch := range []bool{false, true} {
			name := architecture + "/single"
			if batch {
				name = architecture + "/batch"
			}
			b.Run(name, func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					_, err := starlark.Call(thread, globals["exercise"], starlark.Tuple{starlark.String(architecture), starlark.Bool(batch), starlark.MakeInt(128)}, nil)
					if err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
