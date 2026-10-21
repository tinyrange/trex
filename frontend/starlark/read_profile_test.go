package starlarkfrontend

import (
	"go.starlark.net/starlark"
	"testing"
)

func TestReadProfilerFileSlicesAndReset(t *testing.T) {
	thread := &starlark.Thread{Name: "read-profile-test"}
	installRuntimeClock(thread)
	p, err := clockReadProfilerBuiltin(thread, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = starlark.ExecFile(thread, "profile.star", `
def check():
    f = p.file("ABC", "installed/file")
    if f.size != 3 or f.slice(1, 2).read() != "BC": fail("bytes changed")
    s = p.snapshot()
    if s["total"]["calls"] != 1 or s["total"]["bytes"] != 2: fail("missing slice read")
    if s["files"][0]["label"] != "installed/file": fail("lost attribution")
    p.reset()
    if p.snapshot()["total"]["calls"] != 0: fail("reset failed")
check()
`, starlark.StringDict{"p": p})
	if err != nil {
		t.Fatal(err)
	}
}
