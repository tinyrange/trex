//go:build renvo_bundle

package starlarkfrontend

import (
	"bytes"
	"context"
	"crypto/sha256"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/tinyrange/trex/lifecycle"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

// The recipe owns download, extraction, construction and virtual assertions.
// This opt-in host test writes only its final ELF, and compares the recipe's
// cases against native execution of those identical bytes.
func TestHelloRecipeNative(t *testing.T) {
	if os.Getenv("TREX_HELLO_NATIVE") != "1" {
		t.Skip("set TREX_HELLO_NATIVE=1 for the network/native integration workload")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("native ELF comparison requires linux/amd64")
	}
	thread, _, err := newStarlarkRuntime("-")
	if err != nil {
		t.Fatal(err)
	}
	resources, err := lifecycle.ForThread(thread)
	if err != nil {
		t.Fatal(err)
	}
	defer resources.Close()
	globals, err := thread.Load(thread, "//scripts/smoke:hello.star")
	if err != nil {
		t.Fatal(err)
	}
	value, err := starlark.Call(thread, globals["main"], starlark.Tuple{starlark.Tuple{}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	result := value.(*starlark.Dict)
	field := func(d *starlark.Dict, name string) starlark.Value {
		v, ok, e := d.Get(starlark.String(name))
		if e != nil || !ok {
			t.Fatalf("missing %s", name)
		}
		return v
	}
	image, err := starfile.ReadAll(field(result, "binary").(starfile.File))
	if err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(t.TempDir(), "hello")
	if err := os.WriteFile(filename, image, 0700); err != nil {
		t.Fatal(err)
	}
	cases := globals["CASES"].(*starlark.List)
	virtual := field(result, "cases").(*starlark.List)
	if cases.Len() != virtual.Len() {
		t.Fatal("missing virtual cases")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for i := 0; i < cases.Len(); i++ {
		tc := cases.Index(i).(*starlark.Dict)
		name, _ := starlark.AsString(field(tc, "name"))
		t.Run(name, func(t *testing.T) {
			argv := []string{}
			args := field(tc, "args").(*starlark.List)
			for j := 0; j < args.Len(); j++ {
				s, _ := starlark.AsString(args.Index(j))
				argv = append(argv, s)
			}
			command := exec.CommandContext(ctx, filename, argv...)
			command.Args[0] = "./hello"
			command.Env = []string{"LC_ALL=C"}
			var out, diagnostic bytes.Buffer
			command.Stdout = &out
			command.Stderr = &diagnostic
			full, ok, _ := tc.Get(starlark.String("full"))
			if ok && bool(full.Truth()) {
				f, e := os.OpenFile("/dev/full", os.O_WRONLY, 0)
				if e != nil {
					t.Fatal(e)
				}
				defer f.Close()
				command.Stdout = f
			}
			status := 0
			if err := command.Run(); err != nil {
				if exit, ok := err.(*exec.ExitError); ok {
					status = exit.ExitCode()
				} else {
					t.Fatal(err)
				}
			}
			vr := virtual.Index(i).(starlark.HasAttrs)
			vstatus, _ := vr.Attr("status")
			vout, _ := vr.Attr("stdout")
			verr, _ := vr.Attr("stderr")
			expected := 0
			if err := starlark.AsInt(vstatus, &expected); err != nil {
				t.Fatal(err)
			}
			stdout, _ := starlark.AsString(vout)
			stderr, _ := starlark.AsString(verr)
			if status != expected || out.String() != stdout || diagnostic.String() != stderr {
				t.Fatalf("native %d %q %q; virtual %d %q %q", status, out.String(), diagnostic.String(), expected, stdout, stderr)
			}
		})
	}
	t.Logf("identical final ELF: %d bytes, sha256 %x", len(image), sha256.Sum256(image))
}
