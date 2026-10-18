package starlarkfrontend

import (
	"context"
	"errors"
	"fmt"
	"go.starlark.net/starlark"
	"io"
	"io/fs"
	"strings"
)

// Program runs trusted application policy from a closed, caller-owned filesystem.
// Modules never fall back to the working directory. Native builtins retain their
// normal authority; this API is embedding, not a sandbox for untrusted scripts.
type Program struct {
	Files    fs.FS
	Entry    string
	Args     []string
	Builtins starlark.StringDict
	Print    func(string)
	// Optional scoped repl() console. The caller owns the streams and must unblock
	// Input on cancellation; nil Input leaves interactive evaluation unavailable.
	Input               io.Reader
	Output, ErrorOutput io.Writer
}

// RunProgram owns all resources created by the program until main returns.
// Cancellation interrupts Starlark evaluation; native operations retain their
// own cancellation/timeout contracts. Callers must wait for cleanup to complete.
func RunProgram(ctx context.Context, p Program) (err error) {
	if p.Files == nil {
		return fmt.Errorf("program filesystem is nil")
	}
	environment := predeclared()
	for name, value := range p.Builtins {
		if _, exists := environment[name]; exists {
			return fmt.Errorf("program builtin %q shadows runtime", name)
		}
		environment[name] = value
	}
	loader := newModuleLoaderFS(p.Files, environment)
	thread := &starlark.Thread{Name: "application", Load: loader.Load}
	resources := installRuntimeResources(thread)
	defer func() {
		var eval *starlark.EvalError
		if ctx.Err() != nil && errors.As(err, &eval) && strings.HasPrefix(eval.Msg, "Starlark computation cancelled:") {
			err = ctx.Err()
		}
		err = errors.Join(err, resources.Close())
	}()
	if p.Input != nil {
		out, errOut := p.Output, p.ErrorOutput
		if out == nil {
			out = io.Discard
		}
		if errOut == nil {
			errOut = io.Discard
		}
		installStarlarkConsole(thread, newStreamStarlarkConsole(programInput{ctx, p.Input}, out, errOut))
	}
	installRuntimeClock(thread)
	thread.Print = func(_ *starlark.Thread, s string) {
		if p.Print != nil {
			p.Print(s)
		}
	}
	finished := make(chan struct{})
	defer close(finished)
	go func() {
		select {
		case <-ctx.Done():
			thread.Cancel(ctx.Err().Error())
		case <-finished:
		}
	}()
	if err = installPredeclaredModules(thread, loader, environment); err != nil {
		return err
	}
	thread.SetLocal(starlarkEnvironmentKey, environment)
	globals, err := loader.Load(thread, "//"+p.Entry)
	if err != nil {
		return err
	}
	main, ok := globals["main"]
	if !ok {
		return fmt.Errorf("program has no main")
	}
	args := make(starlark.Tuple, len(p.Args))
	for i, s := range p.Args {
		args[i] = starlark.String(s)
	}
	_, err = starlark.Call(thread, main, starlark.Tuple{args}, nil)
	return err
}

// The owner unblocks a native read on cancellation. Treat that canceled read as
// EOF so the console exits instead of replacing cancellation with a closed-file
// error; ordinary input failures still propagate.
type programInput struct {
	ctx   context.Context
	input io.Reader
}

func (r programInput) Read(p []byte) (int, error) {
	if r.ctx.Err() != nil {
		return 0, io.EOF
	}
	n, err := r.input.Read(p)
	if r.ctx.Err() != nil {
		return 0, io.EOF
	}
	return n, err
}
