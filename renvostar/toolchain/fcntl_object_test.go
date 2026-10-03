//go:build renvo_bundle

package toolchain

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"

	"github.com/tinyrange/trex/emulator/shell"
)

func TestLibcFcntlObjectLink(t *testing.T) {
	src, e := os.ReadFile("../../renvo/libc/tests/fcntl_object.c")
	if e != nil {
		t.Fatal(e)
	}
	files, e := shell.NewMemoryFS(64 << 20)
	if e != nil {
		t.Fatal(e)
	}
	env, e := New(files)
	if e != nil {
		t.Fatal(e)
	}
	if e = files.WriteFile("/main.c", src, 0644); e != nil {
		t.Fatal(e)
	}
	var out, diagnostic bytes.Buffer
	r, e := shell.Run(context.Background(), strings.NewReader("cc -c main.c -o main.o && cc main.o -o app && ./app"), "test", shell.Config{FS: files, Dir: "/", Env: map[string]string{"PATH": "/bin"}, Stdout: &out, Stderr: &diagnostic, Command: env.Command})
	if e != nil || r.Status != 0 {
		t.Fatalf("%+v %v %s", r, e, diagnostic.String())
	}
}
