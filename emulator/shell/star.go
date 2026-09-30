package shell

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/tinyrange/trex/lifecycle"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
)

func StarBuiltins() starlark.StringDict {
	return starlark.StringDict{
		"filesystem": starlark.NewBuiltin("filesystem", FilesBuiltin),
		"run":        starlark.NewBuiltin("shell.run", runBuiltin),
	}
}

type capture struct {
	mu      sync.Mutex
	buffer  bytes.Buffer
	maximum int
}

func (c *capture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(p) > c.maximum-c.buffer.Len() {
		return 0, fmt.Errorf("shell: output budget exceeded")
	}
	return c.buffer.Write(p)
}
func (c *capture) String() string { c.mu.Lock(); defer c.mu.Unlock(); return c.buffer.String() }

func stringSequence(value starlark.Value) ([]string, error) {
	seq, ok := value.(starlark.Sequence)
	if !ok {
		return nil, fmt.Errorf("expected sequence of strings")
	}
	it := seq.Iterate()
	defer it.Done()
	out := []string{}
	var item starlark.Value
	for it.Next(&item) {
		s, ok := starlark.AsString(item)
		if !ok {
			return nil, fmt.Errorf("expected string argument")
		}
		out = append(out, s)
	}
	return out, nil
}
func stringMap(value *starlark.Dict) (map[string]string, error) {
	out := map[string]string{}
	for _, item := range value.Items() {
		k, ok := starlark.AsString(item[0])
		v, ok2 := starlark.AsString(item[1])
		if !ok || !ok2 {
			return nil, fmt.Errorf("environment keys and values must be strings")
		}
		out[k] = v
	}
	return out, nil
}
func runBuiltin(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var files *Files
	var source starlark.Value
	dir := "/"
	name := "shell"
	env := starlark.NewDict(0)
	commands := starlark.NewDict(0)
	var argv starlark.Value = starlark.Tuple{}
	var fallback starlark.Value = starlark.None
	var input starlark.Value = starlark.Bytes("")
	steps := int64(100000)
	maximum := 8 << 20
	timeout := int64(120)
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "files", &files, "source", &source, "dir?", &dir, "env?", &env, "args?", &argv, "commands?", &commands, "executable?", &fallback, "stdin?", &input, "name?", &name, "max_steps?", &steps, "maximum_output?", &maximum, "timeout?", &timeout); err != nil {
		return nil, err
	}
	if timeout <= 0 || timeout > 3600 || maximum <= 0 || steps <= 0 {
		return nil, fmt.Errorf("shell.run: positive budgets required; timeout must be <=3600 seconds")
	}
	table := map[string]*Action{}
	for _, item := range commands.Items() {
		p, ok := starlark.AsString(item[0])
		action, ok2 := item[1].(*Action)
		if !ok || !ok2 {
			return nil, fmt.Errorf("commands: expected absolute path -> shell_command")
		}
		if err := validPath(p); err != nil {
			return nil, err
		}
		table[p] = action
	}
	var executable *Action
	if fallback != starlark.None {
		var ok bool
		executable, ok = fallback.(*Action)
		if !ok {
			return nil, fmt.Errorf("executable must be a shell_command")
		}
	}
	arguments, err := stringSequence(argv)
	if err != nil {
		return nil, err
	}
	environment, err := stringMap(env)
	if err != nil {
		return nil, err
	}
	reader := func(value starlark.Value) (io.Reader, error) {
		switch v := value.(type) {
		case starlark.String:
			return bytes.NewBufferString(string(v)), nil
		case starlark.Bytes:
			return bytes.NewBufferString(string(v)), nil
		case starfile.File:
			return io.NewSectionReader(v, 0, v.Size()), nil
		default:
			return nil, fmt.Errorf("expected file, string or bytes")
		}
	}
	script, err := reader(source)
	if err != nil {
		return nil, err
	}
	stdin, err := reader(input)
	if err != nil {
		return nil, err
	}
	resources, err := lifecycle.ForThread(thread)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(resources.Context(), time.Duration(timeout)*time.Second)
	defer cancel()
	out := &capture{maximum: maximum}
	diagnostic := &capture{maximum: maximum}
	result, err := Run(ctx, script, name, Config{FS: files.MemoryFS, Dir: dir, Args: arguments, Env: environment, Stdin: stdin, Stdout: out, Stderr: diagnostic, Command: Commands(table, executable), MaxSteps: steps})
	if err != nil {
		return nil, fmt.Errorf("shell.run: %w (stderr tail: %s)", err, tailDiagnostic(diagnostic.String()))
	}
	return starlarkstruct.FromStringDict(starlark.String("shell_result"), starlark.StringDict{"status": starlark.MakeInt(result.Status), "steps": starlark.MakeInt64(result.Steps), "stdout": starlark.String(out.String()), "stderr": starlark.String(diagnostic.String())}), nil
}
func tailDiagnostic(s string) string {
	if len(s) > 2000 {
		return s[len(s)-2000:]
	}
	return s
}
