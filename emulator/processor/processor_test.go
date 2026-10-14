package processor

import (
	"testing"

	"go.starlark.net/starlark"
)

func TestBoundedARM64MemoryCallsAndStops(t *testing.T) {
	_, err := starlark.ExecFile(&starlark.Thread{Name: "processor-test"}, "processor.star", `
def check(ok, message):
    if not ok:
        fail(message)
def test():
    p=processor(memory=8192)
    p.map(0x1000,4096,data=b"\x00\x04\x00\x91\x20\x00\x00\xf9\xc0\x03\x5f\xd6",access="rx")
    p.map(0x4000,4096)
    p.plugin["calls"]=1
    p.set_register("pc",0x1000)
    p.set_register("x0",41)
    p.set_register("x1",0x4000)
    p.set_register("x30",0xdead)
    r=p.run(1,stop_at=[0xdead])
    check(r.reason=="budget" and r.pc==0x1004 and r.steps==1,"bounded prefix")
    r=p.run(2,stop_at=[0xdead])
    check(r.reason=="breakpoint" and r.pc==0xdead and r.steps==2,"return breakpoint at exact budget")
    check(p.get_register("x0")==42 and p.read(0x4000,8)==b"*\x00\x00\x00\x00\x00\x00\x00","call result/memory")
    r=p.run(10,stop_at=[0xdead])
    check(r.steps==0,"breakpoint must precede instruction fetch")
    p.set_register("pc",0x5000)
    r=p.run(10)
    check(r.reason=="fault" and r.steps==0 and r.detail!="","unmapped instruction fault")
    p.close()
test()
`, starlark.StringDict{"processor": starlark.NewBuiltin("processor", Builtin)})
	if err != nil {
		t.Fatal(err)
	}
}

func TestProcessorRejectsPermissionsAndBounds(t *testing.T) {
	for _, script := range []string{
		`processor(architecture="unknown")`,
		`processor(memory=0)`,
		`processor().run(0)`,
		`processor().map(1,1,access="invalid")`,
		`processor().map(1,1,data=b"long")`,
		`p=processor(); p.map(1,1,access="r"); p.write(1,b"x")`,
		`p=processor(); p.close(); p.run(1)`,
		`processor().read(0,2<<20)`,
	} {
		if _, err := starlark.ExecFile(&starlark.Thread{}, "invalid.star", script, starlark.StringDict{"processor": starlark.NewBuiltin("processor", Builtin)}); err == nil {
			t.Fatal("accepted invalid processor operation", script)
		}
	}
}
