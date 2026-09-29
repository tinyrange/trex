//go:build renvo_bundle

package buildenv

import (
	"bytes"
	"context"
	"github.com/tinyrange/trex/emulator/linux"
	"github.com/tinyrange/trex/emulator/shell"
	"os"
	"strings"
	"testing"
)

func TestLibcHeaderSemantics(t *testing.T) {
	source, err := os.ReadFile("../../renvo/backend/tests/c_header_semantics.c")
	if err != nil {
		t.Fatal(err)
	}
	files, err := shell.NewMemoryFS(16 << 20)
	if err != nil {
		t.Fatal(err)
	}
	env, err := New(files)
	if err != nil {
		t.Fatal(err)
	}
	if err := files.Mkdir("/work"); err != nil {
		t.Fatal(err)
	}
	if err := files.WriteFile("/work/main.c", source, 0644); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	result, err := shell.Run(context.Background(), strings.NewReader("cc main.c -o headers && ./headers"), "headers", shell.Config{FS: files, Dir: "/work", Env: map[string]string{"PATH": "/bin"}, Command: env.Command, Stdout: &output, Stderr: &output})
	if err != nil || result.Status != 0 || output.String() != "PASS\n" {
		t.Fatalf("%+v %v %q", result, err, output.String())
	}
}

func TestErrnoOnlyProcessNames(t *testing.T) {
	files, err := shell.NewMemoryFS(16 << 20)
	if err != nil {
		t.Fatal(err)
	}
	env, err := New(files)
	if err != nil {
		t.Fatal(err)
	}
	source := `#include <errno.h>
int main(void) {
 if (!program_invocation_name || !program_invocation_short_name) return 1;
 const char *name=program_invocation_name, *last=name;
 while (*name) {if (*name=='/') last=name+1; name++;}
 const char *shortname=program_invocation_short_name;
 while (*last && *last==*shortname) {last++;shortname++;}
 return *last || *shortname;
}`
	if err := files.WriteFile("/main.c", []byte(source), 0644); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	r, err := shell.Run(context.Background(), strings.NewReader("cc main.c -o app"), "test", shell.Config{FS: files, Env: map[string]string{"PATH": "/bin"}, Command: env.Command, Stdout: &output, Stderr: &output})
	if err != nil || r.Status != 0 {
		t.Fatalf("compile %+v %v %s", r, err, output.String())
	}
	image, err := files.ReadFile("/app")
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{nil, {""}, {"app"}, {"/nested/path/app"}, {"/nested/path/"}} {
		r, e := linux.Run(context.Background(), bytes.NewReader(image), linux.Config{Args: args})
		if e != nil || r.Status != 0 {
			t.Fatalf("args=%q result=%+v err=%v", args, r, e)
		}
	}
}
