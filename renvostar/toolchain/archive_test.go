package toolchain

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/tinyrange/trex/emulator/shell"
)

func TestArchiveLazyLinkAndReplacement(t *testing.T) {
	files, err := shell.NewMemoryFS(32 << 20)
	if err != nil {
		t.Fatal(err)
	}
	env, err := New(files)
	if err != nil {
		t.Fatal(err)
	}
	for name, src := range map[string]string{
		"main.c":        `extern int first(void); int main(void){return first()==42 ? 0 : 1;}`,
		"first.c":       `extern int second(void); int first(void){return second()+2;}`,
		"second.c":      `int second(void){return 1;}`,
		"replacement.c": `int second(void){return 40;}`,
		"unused.c":      `extern int missing(void); int first(void){return missing();}`,
	} {
		if err = files.WriteFile("/"+name, []byte(src), 0644); err != nil {
			t.Fatal(err)
		}
	}
	script := `set -e
cc -c main.c -o main.o
cc -c first.c -o first.o
cc -c second.c -o very-long-member-name.o
cc -c unused.c -o unused.o
ar cr library.a very-long-member-name.o first.o unused.o
cc -c replacement.c -o very-long-member-name.o
ar r library.a very-long-member-name.o
ranlib library.a
cc main.o library.a -o app
./app
if ld library.a main.o -o wrong-order; then exit 91; fi
if test -f wrong-order; then exit 92; fi
ar cr complete.a main.o first.o very-long-member-name.o unused.o
cc complete.a -o archive-entry
./archive-entry
if ar q library.a main.o; then exit 93; fi
./app
`
	var out, diag bytes.Buffer
	r, err := shell.Run(context.Background(), strings.NewReader(script), "archive", shell.Config{FS: files, Env: map[string]string{"PATH": "/bin"}, Stdout: &out, Stderr: &diag, Command: env.Command})
	if err != nil || r.Status != 0 {
		t.Fatalf("%+v %v %s %s", r, err, out.String(), diag.String())
	}
	if !strings.Contains(diag.String(), "undefined symbol: first") || !strings.Contains(diag.String(), "unsupported ar operation q") {
		t.Fatal(diag.String())
	}
	if runtime.GOOS == "linux" && runtime.GOARCH == "amd64" {
		image, err := files.ReadFile("/app")
		if err != nil {
			t.Fatal(err)
		}
		name := filepath.Join(t.TempDir(), "app")
		if err = os.WriteFile(name, image, 0700); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command(name).CombinedOutput(); err != nil {
			t.Fatalf("%v %q", err, out)
		}
	}
}
