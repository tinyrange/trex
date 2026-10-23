package starlarkfrontend

import (
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
	"testing"
)

func TestGetMessageRunsQueuedWorker(t *testing.T) {
	thread, predeclared, err := newStarlarkRuntime("-")
	if err != nil {
		t.Fatal(err)
	}
	predeclared["image"] = &starfile.Bytes{Name: "queued-message", Data: []byte(relocatablePE32TestImage(t, 0x200000))}
	_, err = starlark.ExecFile(thread, "queued-message.star", `
load("@stdlib//windows/selfreg:win32.star","kernel32_plugin","user32_plugin")
def check(ok):
    if not ok:
        fail("queued message contract")
def exercise(arch):
    m=emulator.machine(architecture=arch,code=b"\xc3")
    k=kernel32_plugin()
    ui=user32_plugin(image,kernel=k)
    m.use([k,ui])
    payload=0x123456789abcdef0 if arch=="amd64" else 0x76543210
    def worker(event):
        result=event.machine.invoke(event.machine.resolve_export("user32.dll",name="PostThreadMessageW"),args=[8,0x8123,payload,payload-1])
        check(result.reason=="return" and result.value==1)
        return 42
    address=m.provide_export(worker,module="worker.dll",name="Work",argc=1)
    queued=m.call(m.resolve_export("kernel32.dll",name="QueueUserWorkItem"),args=[address,0,0])
    check(queued.reason=="return" and queued.value==1)
    check(k.state["threads"][-1]["state"]=="created")
    msg=m.allocate(size=64)
    m.write_u32le(msg+(48 if arch=="amd64" else 28),0xfeedface)
    get=m.resolve_export("user32.dll",name="GetMessageW")
    got=m.call(get,args=[msg,0,0,0])
    check(got.reason=="return" and got.value==1)
    check(k.state["threads"][-1]["result"].value==42)
    check(m.read_u32le(msg+(8 if arch=="amd64" else 4))==0x8123)
    check(m.read_pointer(msg+(16 if arch=="amd64" else 8))==payload)
    check(m.read_pointer(msg+(24 if arch=="amd64" else 12))==payload-1)
    check(m.read_u32le(msg+(48 if arch=="amd64" else 28))==0xfeedface)
    check(m.call(get,args=[msg,0,0,0]).reason=="wait")
exercise("x86")
exercise("amd64")
`, predeclared)
	if err != nil {
		if e, ok := err.(*starlark.EvalError); ok {
			t.Fatal(e.Backtrace())
		}
		t.Fatal(err)
	}
}
