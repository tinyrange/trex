package starlarkfrontend

import (
	"errors"
	"io"
	"strings"
	"testing"

	"go.starlark.net/starlark"
)

type scriptedStarlarkConsole struct {
	lines   []string
	prompts []string
	output  strings.Builder
	errors  strings.Builder
}

func (c *scriptedStarlarkConsole) ReadLine(prompt string) (string, error) {
	c.prompts = append(c.prompts, prompt)
	if len(c.lines) == 0 {
		return "", io.EOF
	}
	line := c.lines[0]
	c.lines = c.lines[1:]
	return line, nil
}

func (c *scriptedStarlarkConsole) WriteOutput(text string) error {
	_, _ = c.output.WriteString(text)
	return nil
}

func (c *scriptedStarlarkConsole) WriteError(text string) error {
	_, _ = c.errors.WriteString(text)
	return nil
}

func TestScopedREPL(t *testing.T) {
	thread, environment, err := newStarlarkRuntime("repl_test.star")
	if err != nil {
		t.Fatal(err)
	}
	console := &scriptedStarlarkConsole{lines: []string{
		`local.append("changed")`,
		`local`,
		`local = ["rebound"]`,
		`1 // 0`,
		`load("@stdlib//:doc.star", "identity")`,
		`identity(42)`,
		`count = 0`,
		`while count < 2:`,
		`    count += 1`,
		``,
		`count`,
	}}
	installStarlarkConsole(thread, console)
	globals, err := starlark.ExecFileOptions(starlarkFileOptions(), thread, "repl_test.star", `
module_value = "module"

def main():
    local = ["before"]
    repl()
    return (local, module_value)
`, environment)
	if err != nil {
		t.Fatal(err)
	}
	result, err := starlark.Call(thread, globals["main"].(starlark.Callable), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	wantResult := `(["before", "changed"], "module")`
	if result.String() != wantResult {
		t.Fatalf("result = %s, want %s", result, wantResult)
	}
	if got, want := console.output.String(), "[\"before\", \"changed\"]\n42\n2\n"; got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
	if !strings.Contains(console.errors.String(), "division by zero") {
		t.Fatalf("errors = %q, want evaluation failure", console.errors.String())
	}
	if len(console.prompts) < 4 || console.prompts[0] != ">>> " || !containsString(console.prompts, "... ") {
		t.Fatalf("prompts = %q", console.prompts)
	}
}

func TestREPLRequiresConsoleAndCaller(t *testing.T) {
	thread, environment, err := newStarlarkRuntime("repl_test.star")
	if err != nil {
		t.Fatal(err)
	}
	globals, err := starlark.ExecFileOptions(starlarkFileOptions(), thread, "repl_test.star", `
def main():
    repl()
`, environment)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := starlark.Call(thread, globals["main"].(starlark.Callable), nil, nil); err == nil || !strings.Contains(err.Error(), "no line console") {
		t.Fatalf("repl without console error = %v", err)
	}
	if _, err := replBuiltin(thread, nil, nil, nil); err == nil || !strings.Contains(err.Error(), "Starlark function") {
		t.Fatalf("direct repl error = %v", err)
	}
}

func TestStarlarkHelpUsesRuntimeDocumentation(t *testing.T) {
	thread, environment, err := newStarlarkRuntime("help_test.star")
	if err != nil {
		t.Fatal(err)
	}
	console := &scriptedStarlarkConsole{}
	installStarlarkConsole(thread, console)
	globals, err := starlark.ExecFileOptions(starlarkFileOptions(), thread, "help_test.star", `
def main():
    help(binary.read_u32le)
    help("binary.i16be")
    builder = binary.builder()
    help(builder.patch_u64le)
    help(runtime.stage_cache)
`, environment)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := starlark.Call(thread, globals["main"].(starlark.Callable), nil, nil); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"binary.read_u32le(source, offset=0) -> int",
		"binary.i16be(value) -> bytes",
		"binary.builder.patch_u64le(offset, value) -> binary.builder",
		"runtime.stage_cache() -> runtime.stage_cache",
	} {
		if !strings.Contains(console.output.String(), expected) {
			t.Errorf("help output omits %q:\n%s", expected, console.output.String())
		}
	}
}

func TestStreamStarlarkConsole(t *testing.T) {
	var output, errorOutput strings.Builder
	console := newStreamStarlarkConsole(strings.NewReader("one\r\ntwo"), &output, &errorOutput)
	line, err := console.ReadLine(">>> ")
	if err != nil || line != "one" {
		t.Fatalf("first line = %q, %v", line, err)
	}
	line, err = console.ReadLine("... ")
	if err != nil || line != "two" {
		t.Fatalf("second line = %q, %v", line, err)
	}
	_, err = console.ReadLine(">>> ")
	if !errors.Is(err, io.EOF) {
		t.Fatalf("EOF = %v", err)
	}
	if output.String() != ">>> ... >>> " {
		t.Fatalf("prompts = %q", output.String())
	}
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
