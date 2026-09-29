//go:build renvo_bundle

package buildenv

import (
	"bytes"
	"context"
	"github.com/tinyrange/trex/emulator/shell"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSeparateLibcObjectRuntime(t *testing.T) {
	source, err := os.ReadFile("../../renvo/libc/tests/object_runtime.c")
	if err != nil {
		t.Fatal(err)
	}
	files, err := shell.NewMemoryFS(32 << 20)
	if err != nil {
		t.Fatal(err)
	}
	env, err := New(files)
	if err != nil {
		t.Fatal(err)
	}
	if err = files.Mkdir("/virtual"); err != nil {
		t.Fatal(err)
	}
	if err = files.WriteFile("/main.c", source, 0644); err != nil {
		t.Fatal(err)
	}
	var out, diag bytes.Buffer
	r, err := shell.Run(context.Background(), strings.NewReader("cc -c main.c -o main.o && cc main.o -o /virtual/app && EXAMPLE=value=tail /virtual/app argument"), "test", shell.Config{FS: files, Env: map[string]string{"PATH": "/bin"}, Command: env.Command, Stdout: &out, Stderr: &diag})
	if err != nil || r.Status != 0 || out.String() != "PASS\n" {
		t.Fatalf("%+v %v %q %s", r, err, out.String(), diag.String())
	}
	if runtime.GOOS == "linux" && runtime.GOARCH == "amd64" {
		image, err := files.ReadFile("/virtual/app")
		if err != nil {
			t.Fatal(err)
		}
		name := filepath.Join(t.TempDir(), "app")
		if err = os.WriteFile(name, image, 0700); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(name, "argument")
		cmd.Args[0] = "/virtual/app"
		cmd.Env = []string{"EXAMPLE=value=tail"}
		if out, err := cmd.CombinedOutput(); err != nil || string(out) != "PASS\n" {
			t.Fatalf("native %v %q", err, out)
		}
	}
}
