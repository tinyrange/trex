package starlarkfrontend

import (
	"os"
	"strings"
	"testing"

	"github.com/tinyrange/trex/lifecycle"
	"go.starlark.net/starlark"
)

func TestTemporaryOverlayCleanupAfterScriptFailure(t *testing.T) {
	thread, env, err := newStarlarkRuntime("-")
	if err != nil {
		t.Fatal(err)
	}
	resources, err := lifecycle.ForThread(thread)
	if err != nil {
		t.Fatal(err)
	}
	defer resources.Close()
	dir := t.TempDir()
	env["overlay_dir"] = starlark.String(dir)
	_, err = starlark.ExecFile(thread, "overlay.star", `
def run():
    base = block.device(binary.view(b"\x5a" * 4096))
    working = block.temporary_overlay(base, directory=overlay_dir)
    working.write(17, b"abc")
    if block.view(working).bytes(16,5) != b"\x5aabc\x5a": fail("overlay read mismatch")
    if block.view(base).bytes(17,3) != b"\x5a\x5a\x5a": fail("base modified")
    fail("deliberate script failure")
run()
`, env)
	if err == nil || !strings.Contains(err.Error(), "deliberate script failure") {
		t.Fatalf("unexpected script result: %v", err)
	}
	files, err := os.ReadDir(dir)
	if err != nil || len(files) != 1 {
		t.Fatalf("backing not created: %v %v", files, err)
	}
	if err := resources.Close(); err != nil {
		t.Fatal(err)
	}
	files, err = os.ReadDir(dir)
	if err != nil || len(files) != 0 {
		t.Fatalf("backing leaked: %v %v", files, err)
	}
}
