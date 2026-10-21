package toolchain

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/tinyrange/trex/emulator/shell"
)

func TestVirtualLinkerExecutesSeparateObjects(t *testing.T) {
	files, err := shell.NewMemoryFS(16 << 20)
	if err != nil {
		t.Fatal(err)
	}
	env, err := New(files)
	if err != nil {
		t.Fatal(err)
	}
	for name, source := range map[string]string{
		"main.c":   `extern int answer(int); extern int bias; int main(int argc, char **argv) { return answer(argc) + bias + (argv[1][0] == 'x'); }`,
		"answer.c": `int bias = 3; int answer(int n) { return n + 36; }`,
	} {
		if err := files.WriteFile("/"+name, []byte(source), 0644); err != nil {
			t.Fatal(err)
		}
	}
	script := `set -e
umask 077
cc -c main.c -o main.o
cc -c answer.c -o answer.o
command -v ld
ld -v
printf '%s\n' '-static -s -o linked main.o answer.o' >link.rsp
ld @link.rsp
cc -g -O2 main.o answer.o -o cc-linked
set +e
./cc-linked x
test "$?" = 42 || exit 96
./linked x
printf 'exit=%s\n' "$?"
if ld main.o -o broken; then exit 99; fi
if test -f broken; then exit 98; fi
if ld -shared main.o answer.o -o linked; then exit 97; fi
./linked x
printf 'retained=%s\n' "$?"
`
	var out, diagnostics bytes.Buffer
	result, err := shell.Run(context.Background(), strings.NewReader(script), "link.sh", shell.Config{FS: files, Env: map[string]string{"PATH": "/bin"}, Command: env.Command, Stdout: &out, Stderr: &diagnostics})
	if err != nil || result.Status != 0 {
		t.Fatalf("%+v %v stdout=%s stderr=%s", result, err, out.String(), diagnostics.String())
	}
	if out.String() != "/bin/ld\nrenvo ld (static Linux/amd64 object linker)\nexit=42\nretained=42\n" || !strings.Contains(diagnostics.String(), "undefined symbol:") || !strings.Contains(diagnostics.String(), "unsupported linker option -shared") {
		t.Fatalf("stdout=%s stderr=%s", out.String(), diagnostics.String())
	}
	st, err := files.Stat("/linked")
	if err != nil || st.Mode().Perm() != 0700 {
		t.Fatalf("mode: %v %v", st, err)
	}
}
