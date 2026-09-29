package buildenv

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/tinyrange/trex/emulator/shell"
)

func TestShellCompileAndRun(t *testing.T) {
	files, err := shell.NewMemoryFS(64 << 20)
	if err != nil {
		t.Fatal(err)
	}
	env, err := New(files)
	if err != nil {
		t.Fatal(err)
	}
	script := `mkdir build
cd build
cat >main.c <<'EOF'
int main(int argc, char **argv) {
 return argc == 2 && argv[1][0] == 'x' ? 37 : 99;
}
EOF
cc -o app main.c
./app x
printf 'status=%s\n' "$?"
`
	var out, diagnostics bytes.Buffer
	result, err := shell.Run(context.Background(), strings.NewReader(script), "build.sh", shell.Config{FS: files, Env: map[string]string{"PATH": "/bin"}, Stdout: &out, Stderr: &diagnostics, Command: env.Command})
	if err != nil || result.Status != 0 || out.String() != "status=37\n" {
		t.Fatalf("%+v %v output=%q stderr=%q", result, err, out.String(), diagnostics.String())
	}
	image, err := files.ReadFile("/build/app")
	if err != nil || !bytes.HasPrefix(image, []byte("\x7fELF")) {
		t.Fatalf("not an ELF: %v", err)
	}
}
func TestCompilerDiagnosticIsAnOrdinaryFailure(t *testing.T) {
	files, err := shell.NewMemoryFS(64 << 20)
	if err != nil {
		t.Fatal(err)
	}
	env, err := New(files)
	if err != nil {
		t.Fatal(err)
	}
	var out, diagnostics bytes.Buffer
	script := `printf 'int main(void) { return unknown; }' >bad.c; if cc bad.c; then exit 99; else printf rejected; fi`
	result, err := shell.Run(context.Background(), strings.NewReader(script), "bad.sh", shell.Config{FS: files, Env: map[string]string{"PATH": "/bin"}, Stdout: &out, Stderr: &diagnostics, Command: env.Command})
	if err != nil || result.Status != 0 || out.String() != "rejected" || !strings.Contains(diagnostics.String(), "undefined identifier") {
		t.Fatalf("%+v %v %q %q", result, err, out.String(), diagnostics.String())
	}
}
