package starlarkfrontend

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"

	"go.starlark.net/starlark"
	"go.starlark.net/syntax"
)

const (
	starlarkConsoleKey  = "trex.runtime.console"
	starlarkREPLActive  = "trex.runtime.repl.active"
	maxREPLLineSize     = 1 << 20
	maxREPLCompoundSize = 8 << 20
)

// starlarkConsole is the portable line-oriented boundary used by the REPL.
// Native terminals, tests, and browser hosts can provide independent backends.
type starlarkConsole interface {
	ReadLine(prompt string) (string, error)
	WriteOutput(text string) error
	WriteError(text string) error
}

type streamStarlarkConsole struct {
	input  *bufio.Reader
	output io.Writer
	errors io.Writer
}

func newStreamStarlarkConsole(input io.Reader, output, errors io.Writer) starlarkConsole {
	return &streamStarlarkConsole{input: bufio.NewReader(input), output: output, errors: errors}
}

func (c *streamStarlarkConsole) ReadLine(prompt string) (string, error) {
	if _, err := io.WriteString(c.output, prompt); err != nil {
		return "", err
	}
	line, err := c.input.ReadString('\n')
	if len(line) > 0 && errors.Is(err, io.EOF) {
		err = nil
	}
	line = strings.TrimSuffix(line, "\n")
	line = strings.TrimSuffix(line, "\r")
	return line, err
}

func (c *streamStarlarkConsole) WriteOutput(text string) error {
	_, err := io.WriteString(c.output, text)
	return err
}

func (c *streamStarlarkConsole) WriteError(text string) error {
	_, err := io.WriteString(c.errors, text)
	return err
}

func installStarlarkConsole(thread *starlark.Thread, console starlarkConsole) {
	thread.SetLocal(starlarkConsoleKey, console)
}

func consoleForThread(thread *starlark.Thread) (starlarkConsole, error) {
	if thread == nil {
		return nil, fmt.Errorf("console: Starlark runtime is unavailable")
	}
	console, ok := thread.Local(starlarkConsoleKey).(starlarkConsole)
	if !ok || console == nil {
		return nil, fmt.Errorf("console: no line console is installed by this runtime backend")
	}
	return console, nil
}

func replBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("repl", args, kwargs); err != nil {
		return nil, err
	}
	if thread == nil || thread.CallStackDepth() < 2 {
		return nil, fmt.Errorf("repl: must be called from a Starlark function")
	}
	if active, _ := thread.Local(starlarkREPLActive).(bool); active {
		return nil, fmt.Errorf("repl: nested REPL sessions are not supported")
	}
	console, err := consoleForThread(thread)
	if err != nil {
		return nil, fmt.Errorf("repl: %w", err)
	}

	globals, err := replCallerScope(thread)
	if err != nil {
		return nil, err
	}
	previous := thread.Local(starlarkREPLActive)
	thread.SetLocal(starlarkREPLActive, true)
	defer thread.SetLocal(starlarkREPLActive, previous)

	options := *starlarkFileOptions()
	options.LoadBindsGlobally = true
	for {
		if err := executeREPLChunk(&options, thread, globals, console); err != nil {
			if errors.Is(err, io.EOF) {
				return starlark.None, nil
			}
			return nil, fmt.Errorf("repl: %w", err)
		}
	}
}

func replCallerScope(thread *starlark.Thread) (starlark.StringDict, error) {
	frame := thread.DebugFrame(1)
	function, ok := frame.Callable().(*starlark.Function)
	if !ok {
		return nil, fmt.Errorf("repl: caller is %s, want Starlark function", frame.Callable().Name())
	}
	globals := make(starlark.StringDict)
	for name, value := range function.Module().Predeclared() {
		globals[name] = value
	}
	for name, value := range function.Globals() {
		globals[name] = value
	}
	for index := 0; index < function.NumFreeVars(); index++ {
		binding, value := function.FreeVar(index)
		if value != nil {
			globals[binding.Name] = value
		}
	}
	for index := 0; index < frame.NumLocals(); index++ {
		binding, value := frame.Local(index)
		if value != nil {
			globals[binding.Name] = value
		}
	}
	return globals, nil
}

func executeREPLChunk(options *syntax.FileOptions, thread *starlark.Thread, globals starlark.StringDict, console starlarkConsole) error {
	first := true
	eof := false
	total := 0
	readline := func() ([]byte, error) {
		prompt := "... "
		if first {
			prompt = ">>> "
			first = false
		}
		line, err := console.ReadLine(prompt)
		if errors.Is(err, io.EOF) {
			eof = true
			return nil, io.EOF
		}
		if err != nil {
			return nil, err
		}
		if len(line) > maxREPLLineSize {
			return nil, fmt.Errorf("input line exceeds %d bytes", maxREPLLineSize)
		}
		total += len(line) + 1
		if total > maxREPLCompoundSize {
			return nil, fmt.Errorf("compound input exceeds %d bytes", maxREPLCompoundSize)
		}
		return append([]byte(line), '\n'), nil
	}

	file, err := options.ParseCompoundStmt("<repl>", readline)
	if err != nil {
		if eof {
			return io.EOF
		}
		return writeREPLError(console, err)
	}
	if expression := replSoleExpression(file); expression != nil {
		value, err := starlark.EvalExprOptions(file.Options, thread, expression, globals)
		if err != nil {
			return writeREPLError(console, err)
		}
		globals["_"] = value
		if value != starlark.None {
			return console.WriteOutput(value.String() + "\n")
		}
		return nil
	}
	if err := starlark.ExecREPLChunk(file, thread, globals); err != nil {
		return writeREPLError(console, err)
	}
	return nil
}

func replSoleExpression(file *syntax.File) syntax.Expr {
	if len(file.Stmts) == 1 {
		if statement, ok := file.Stmts[0].(*syntax.ExprStmt); ok {
			return statement.X
		}
	}
	return nil
}

func writeREPLError(console starlarkConsole, err error) error {
	message := err.Error()
	if evaluation, ok := err.(*starlark.EvalError); ok {
		message = evaluation.Backtrace()
	}
	if writeErr := console.WriteError(message + "\n"); writeErr != nil {
		return writeErr
	}
	return nil
}
