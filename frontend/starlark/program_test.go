package starlarkfrontend

import (
	"bytes"
	"context"
	"errors"
	"go.starlark.net/starlark"
	"io"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

func TestEmbeddedProgramIsolationAndArguments(t *testing.T) {
	var result string
	files := fstest.MapFS{
		"app.star": {Data: []byte(`load("//lib:message.star", "prefix")
def main(args):
    report(prefix + args[0])
`)},
		"lib/message.star": {Data: []byte(`prefix = "embedded:"
`)},
	}
	err := RunProgram(context.Background(), Program{Files: files, Entry: "app.star", Args: []string{"ok"}, Builtins: starlark.StringDict{
		"report": starlark.NewBuiltin("report", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			err := starlark.UnpackArgs("report", args, kwargs, "s", &result)
			return starlark.None, err
		}),
	}})
	if err != nil || result != "embedded:ok" {
		t.Fatalf("result %q: %v", result, err)
	}
	files["app.star"] = &fstest.MapFile{Data: []byte(`load("//cli_test.star", "main")`)}
	if err := RunProgram(context.Background(), Program{Files: files, Entry: "app.star"}); err == nil {
		t.Fatal("missing embedded module accepted")
	}
}
func TestEmbeddedProgramCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := RunProgram(ctx, Program{Files: fstest.MapFS{"app.star": {Data: []byte(`def main(args):
    while True:
        pass
`)}}, Entry: "app.star"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v", err)
	}
}

func TestEmbeddedProgramScopedConsole(t *testing.T) {
	var output, diagnostics bytes.Buffer
	err := RunProgram(context.Background(), Program{
		Files: fstest.MapFS{"app.star": {Data: []byte(`def main(args):
    owned = [41]
    repl()
    if owned != [42]: fail("console lost caller-owned value")
`)}}, Entry: "app.star",
		Input:  strings.NewReader("owned[0] += 1\nowned[0]\n"),
		Output: &output, ErrorOutput: &diagnostics,
	})
	if err != nil || diagnostics.Len() != 0 || !strings.Contains(output.String(), "42") {
		t.Fatalf("console err=%v output=%q diagnostics=%q", err, output.String(), diagnostics.String())
	}
}

func TestEmbeddedConsoleCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	done := make(chan error, 1)
	go func() {
		done <- RunProgram(ctx, Program{
			Files: fstest.MapFS{"app.star": {Data: []byte(`def main(args):
    repl()
    while True:
        pass
`)}}, Entry: "app.star", Input: reader,
		})
	}()
	// Pipe Write synchronizes with the console read; cancellation then unblocks
	// its next read just as the embedding application's stdin owner does.
	if _, err := writer.Write([]byte("x = 1\n")); err != nil {
		t.Fatal(err)
	}
	cancel()
	reader.CloseWithError(io.ErrClosedPipe)
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("lost cancellation: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("console did not exit after cancellation")
	}
}
