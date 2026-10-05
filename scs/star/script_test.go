package script

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	scsnative "github.com/tinyrange/trex/scs/native"
	"github.com/tinyrange/trex/scs/repo"
)

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func setup(t *testing.T) (*repo.Repository, *repo.Workspace, string) {
	t.Helper()
	name := filepath.Join(t.TempDir(), "test.scs")
	r, err := scsnative.Create(name)
	must(t, err)
	t.Cleanup(func() { r.Close() })
	w := r.Empty()
	must(t, w.WriteFile("README.md", []byte("hello\nworld\n")))
	_, err = w.Publish("main")
	must(t, err)
	return r, w, name
}
func TestWorkspaceScript(t *testing.T) {
	r, w, name := setup(t)
	var output bytes.Buffer
	source := `
def check(ok):
    if not ok:
        fail("assertion failed")
check(workspace.read_file("README.md") == "hello\nworld\n")
part = workspace.read_file("README.md", line_start=2, output_limit=3)
check(part.content == "wor" and part.total_lines == 2 and part.truncated_bytes == 3)
check(workspace.read_file("README.md", line_start=10).content == "")
ro = workspace.readonly()
workspace.mkdir("src")
workspace.write_file("src/code.go", "package example\n// hello\n")
workspace.replace("README.md", "hello", "goodbye")
check(ro.read_file("README.md") == "goodbye\nworld\n")
workspace.write_file("src/binary", b"\x00\xff")
workspace.write_file("src/trash", "delete")
workspace.delete("src/trash")
workspace.rename("src", "lib")
workspace.chmod("lib/code.go", 0o755)
workspace.symlink("link", "lib/code.go")
check(workspace.readlink("link") == "lib/code.go")
check(workspace.stat("lib/code.go").mode == 0o755)
check(workspace.glob("**/*.go") == ["lib/code.go"])
check(workspace.list_dir("lib") == ["binary", "code.go"])
result = workspace.search(["package", "hello"], glob="**/*.go")
check(result.match_count == 2 and result.matches[1].line == 2 and result.matches[1].column == 4)
check(workspace.search("hello", max_matches=0).truncated)
check(workspace.search("hello", output_limit=0).truncated)
check(workspace.search(r"pack[a-z]+", regex=True).match_count == 1)
base = workspace.snapshot()
a = workspace.fork()
b = workspace.fork()
a.write_file("README.md", "agent a")
b.write_file("README.md", "agent b")
check(workspace.read_file("README.md") == "goodbye\nworld\n")
a.publish("a")
b.publish("b")
workspace.publish("main")
print("done")
`
	must(t, Run(context.Background(), w, "workflow.star", []byte(source), Options{Print: &output}))
	if output.String() != "done\n" {
		t.Fatal(output.String())
	}
	must(t, r.Close())
	r, err := scsnative.Open(name)
	must(t, err)
	defer r.Close()
	for n, want := range map[string]string{"main": "goodbye\nworld\n", "a": "agent a", "b": "agent b"} {
		w, err := r.Checkout(n)
		must(t, err)
		data, err := w.ReadFile("README.md")
		must(t, err)
		if string(data) != want {
			t.Fatalf("%s: %q", n, data)
		}
	}
}
func TestScriptFailurePublicationBoundary(t *testing.T) {
	r, w, name := setup(t)
	source := `workspace.write_file("README.md", "durable")
workspace.publish("main")
workspace.write_file("README.md", "ephemeral")
fail("stop")`
	if err := Run(context.Background(), w, "fail.star", []byte(source), Options{}); err == nil {
		t.Fatal("expected failure")
	}
	must(t, r.Close())
	r, err := scsnative.Open(name)
	must(t, err)
	defer r.Close()
	w, err = r.Checkout("main")
	must(t, err)
	data, err := w.ReadFile("README.md")
	must(t, err)
	if string(data) != "durable" {
		t.Fatalf("got %q", data)
	}
}
func TestStarlarkCapabilitiesAndLimits(t *testing.T) {
	_, w, _ := setup(t)
	for _, source := range []string{
		`workspace.write_file("README.md", "no")`, `workspace.publish("new")`, `workspace.fork()`, `workspace.snapshot()`,
	} {
		err := Run(context.Background(), w.Readonly(), "readonly.star", []byte(source), Options{})
		if err == nil || !strings.Contains(err.Error(), "read-only") {
			t.Fatalf("%s: %v", source, err)
		}
	}
	for _, source := range []string{`open("/etc/passwd")`, `load("/etc/passwd", "x")`, `workspace.path()`, `workspace.read_file("../escape")`} {
		if err := Run(context.Background(), w, "denied.star", []byte(source), Options{}); err == nil {
			t.Fatalf("accepted %s", source)
		}
	}
	if err := Run(context.Background(), w, "loop.star", []byte("while True:\n    pass\n"), Options{MaxSteps: 1000}); err == nil || !strings.Contains(err.Error(), "steps") {
		t.Fatalf("step budget: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	if err := Run(ctx, w, "loop.star", []byte("while True:\n    pass\n"), Options{MaxSteps: 1 << 60}); err == nil {
		t.Fatal("timeout failed")
	}
	bad := []byte("workspace.write_file('README.md', 'bad')\nthis is not valid syntax !")
	if err := Run(context.Background(), w, "syntax.star", bad, Options{}); err == nil {
		t.Fatal("syntax accepted")
	}
	data, err := w.ReadFile("README.md")
	must(t, err)
	if string(data) != "hello\nworld\n" {
		t.Fatal("syntax error ran earlier statements")
	}
}
func TestSearchBoundsAndBinary(t *testing.T) {
	_, w, _ := setup(t)
	must(t, w.WriteFile("binary", []byte("world\x00")))
	must(t, w.WriteFile("large", bytes.Repeat([]byte("x"), (8<<20)+1)))
	source := `r = workspace.search("world")
if r.match_count != 1 or r.skipped_large_files != 1:
    fail("binary/large file filtering")
r = workspace.read_file("README.md", output_limit=0)
if r.content != "" or not r.truncated:
    fail("read bound")
workspace.write_file("empty", "")
if workspace.read_file("empty", line_start=1).total_lines != 0:
    fail("empty file")
`
	must(t, Run(context.Background(), w, "bounds.star", []byte(source), Options{}))
	for _, expr := range []string{`workspace.read_file("README.md", line_start=0)`, `workspace.read_file("README.md", output_limit=-1)`, `workspace.search("x", max_matches=-1)`, `workspace.search("[", regex=True)`} {
		if err := Run(context.Background(), w, "bad.star", []byte(expr), Options{}); err == nil {
			t.Fatalf("accepted %s", expr)
		}
	}
}
func TestRunDoesNotImplicitlyPublish(t *testing.T) {
	r, w, name := setup(t)
	old := r.Refs()["main"]
	must(t, Run(context.Background(), w, "edit.star", []byte(`workspace.write_file("README.md", "unsaved")`), Options{}))
	must(t, r.Close())
	r, err := scsnative.Open(name)
	must(t, err)
	defer r.Close()
	if r.Refs()["main"] != old {
		t.Fatal("implicit publication")
	}
	// The repository remains one file; no index, lock, or journal sidecars.
	entries, err := os.ReadDir(filepath.Dir(name))
	must(t, err)
	if len(entries) != 1 {
		t.Fatalf("sidecars: %v", entries)
	}
}
