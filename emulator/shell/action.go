package shell

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"strings"

	"go.starlark.net/starlark"
)

// Action is an immutable portable command capability. Recipes choose the
// executable paths; shell workers invoke Go, never a Starlark callback.
type Action struct {
	Name string
	Run  CommandHandler
}

func (a *Action) String() string      { return "<shell command " + a.Name + ">" }
func (*Action) Type() string          { return "shell_command" }
func (*Action) Freeze()               {}
func (*Action) Truth() starlark.Bool  { return true }
func (*Action) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: shell_command") }

// Commands copies the recipe's dispatch table before starting any workers.
// It follows guest PATH and execute permissions; fallback may recognize an
// executable format or return ErrUnhandled for the shell's script loader.
func Commands(actions map[string]*Action, fallback *Action) CommandHandler {
	table := make(map[string]*Action, len(actions))
	for name, action := range actions {
		table[name] = action
	}
	return func(ctx context.Context, in Invocation) (int, error) {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		if len(in.Args) == 0 {
			return 0, fmt.Errorf("shell: empty command")
		}
		resolve := func(name string) string {
			if path.IsAbs(name) {
				return path.Clean(name)
			}
			return path.Join(in.Dir, name)
		}
		names := []string{resolve(in.Args[0])}
		if !strings.Contains(in.Args[0], "/") {
			names = nil
			search, present := in.Env["PATH"]
			if !present {
				return 0, ErrUnhandled
			}
			for _, dir := range strings.Split(search, ":") {
				names = append(names, resolve(path.Join(dir, in.Args[0])))
			}
		}
		for _, name := range names {
			info, err := in.FS.Stat(name)
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			if err != nil {
				return 0, err
			}
			if info.IsDir() || info.Mode().Perm()&0111 == 0 {
				continue
			}
			if action := table[name]; action != nil {
				return action.Run(ctx, in)
			}
			if fallback != nil {
				in.Executable = name
				return fallback.Run(ctx, in)
			}
			return 0, ErrUnhandled
		}
		return 0, ErrUnhandled
	}
}
