package starlarkfrontend

import (
	"github.com/tinyrange/trex/lifecycle"
	"go.starlark.net/starlark"
	"testing"
)

func TestFFSStarlarkConstruction(t *testing.T) {
	thread, env, err := newStarlarkRuntime("-")
	if err != nil {
		t.Fatal(err)
	}
	resources, err := lifecycle.ForThread(thread)
	if err != nil {
		t.Fatal(err)
	}
	defer resources.Close()
	_, err = starlark.ExecFile(thread, "ffs.star", `
def check():
    image = filesystem.ffs_build([
     {"path":"bin/sh", "mode":0o100755, "data":"original-bytes"},
     {"path":"bin/link", "mode":0o100755, "hardlink":True, "target":"bin/sh"},
     {"path":"tmp", "mode":0o041777},
    ], size=8<<20)
    view = filesystem.ufs(image)
    if view.find("/bin/sh").data.bytes() != b"original-bytes": fail("payload mismatch")
    if view.find("/bin/sh").inode != view.find("/bin/link").inode: fail("lost hardlink")
    if view.find("/tmp").mode != 0o041777: fail("lost sticky bit")
    if not hasattr(cc, "boot_bsd"): fail("missing direct BSD API")
    failed = cc.boot_bsd("freebsd", binary.view(b"not ELF"), "ready", root=image)
    if failed.success or "ELF" not in failed.error: fail("invalid kernel accepted")
    if filesystem.ufs(failed.root).find("/bin/sh").data.bytes() != b"original-bytes": fail("failed-boot root snapshot lost")
check()
`, env)
	if err != nil {
		t.Fatal(err)
	}
}
