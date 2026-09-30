package shell

import (
	"context"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/tinyrange/trex/lifecycle"
	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
)

func TestStarlarkCommandPipeline(t *testing.T) {
	thread := &starlark.Thread{Name: "pipeline"}
	resources := lifecycle.Install(thread)
	defer resources.Close()
	producer := &Action{Name: "produce", Run: func(_ context.Context, in Invocation) (int, error) {
		_, err := io.WriteString(in.Stdout, strings.Repeat("x", 128<<10))
		return 0, err
	}}
	consumer := &Action{Name: "consume", Run: func(_ context.Context, in Invocation) (int, error) {
		n, err := io.Copy(io.Discard, in.Stdin)
		if err == nil {
			_, err = fmt.Fprintln(in.Stdout, n)
		}
		return 0, err
	}}
	globals, err := starlark.ExecFile(thread, "pipeline.star", `
f = shell.filesystem()
f.mkdir("/bin")
f.write("/bin/produce", "", mode=0o755)
f.write("/bin/consume", "", mode=0o755)
result = shell.run(files=f, source="produce | consume", env={"PATH":"/bin"}, commands={"/bin/produce":producer,"/bin/consume":consumer}, timeout=2)
`, starlark.StringDict{"shell": &starlarkstruct.Module{Name: "shell", Members: StarBuiltins()}, "producer": producer, "consumer": consumer})
	if err != nil {
		t.Fatal(err)
	}
	result := globals["result"].(starlark.HasAttrs)
	out, _ := result.Attr("stdout")
	status, _ := result.Attr("status")
	if out != starlark.String("131072\n") || status != starlark.MakeInt(0) {
		t.Fatalf("%s %s", status, out)
	}
}
func TestStarlarkExecutionBounds(t *testing.T) {
	for _, tc := range []struct {
		name, source, want string
		cancel             bool
	}{
		{"output", `shell.run(files=f,source="cat",stdin="x"*100,maximum_output=10)`, "output budget exceeded", false},
		{"steps", `shell.run(files=f,source="while :; do :; done",max_steps=10)`, "budget", false},
		{"cancel", `shell.run(files=f,source="sleep 100",timeout=1)`, "canceled", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			thread := &starlark.Thread{}
			resources := lifecycle.Install(thread)
			defer resources.Close()
			if tc.cancel {
				resources.Close()
			}
			_, err := starlark.ExecFile(thread, "bounds.star", "f=shell.filesystem()\n"+tc.source, starlark.StringDict{"shell": &starlarkstruct.Module{Name: "shell", Members: StarBuiltins()}})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %q, got %v", tc.want, err)
			}
		})
	}
}

func TestStarlarkFileSnapshotAndDevices(t *testing.T) {
	thread := &starlark.Thread{}
	env := starlark.StringDict{"shell": &starlarkstruct.Module{Name: "shell", Members: StarBuiltins()}}
	globals, err := starlark.ExecFile(thread, "files.star", `
f=shell.filesystem(maximum=4)
f.mkdir("/work")
f.write("/work/a", "abcd", mode=0o751, mtime=123)
old=f.find("/work/a")
metadata=f.stat("/work/a")
f.write("/work/a", "new")
# Import a file snapshot after removing the mutable file to stay within budget.
f.remove("/work/a")
f.write("/work/b", old)
result=f.find("/work/b").read()
`, env)
	if err != nil {
		t.Fatal(err)
	}
	if globals["result"] != starlark.String("abcd") {
		t.Fatal("file snapshot/import changed")
	}
	metadata := globals["metadata"].(starlark.HasAttrs)
	mode, _ := metadata.Attr("mode")
	mtime, _ := metadata.Attr("mtime")
	if mode != starlark.MakeInt(0751) || mtime != starlark.MakeInt(123) {
		t.Fatalf("mode=%s mtime=%s", mode, mtime)
	}
	env["f"] = globals["f"]
	for _, source := range []string{`f.find("/dev/full")`, `f.find("/dev/null")`, `f.find("/work")`, `f.find("/work/../work/b")`, `f.write("/work/c","x")`} {
		if _, err := starlark.ExecFile(thread, "invalid.star", source, env); err == nil {
			t.Fatalf("accepted %s", source)
		}
	}
}
