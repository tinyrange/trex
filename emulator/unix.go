package emulator

import (
	"bytes"
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/tinyrange/trex/emulator/linux"
	"github.com/tinyrange/trex/emulator/shell"
	"go.starlark.net/starlark"
)

func linuxCommand(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	maximum := uint64(10000000)
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "max_instructions?", &maximum); err != nil {
		return nil, err
	}
	if maximum == 0 {
		return nil, fmt.Errorf("max_instructions must be positive")
	}
	return &shell.Action{Name: "linux/amd64", Run: func(ctx context.Context, in shell.Invocation) (int, error) {
		files, ok := in.FS.(*shell.MemoryFS)
		if !ok {
			return 0, fmt.Errorf("linux: expected Unix filesystem")
		}
		data, err := files.ReadFile(in.Executable)
		if err != nil {
			return 0, err
		}
		if !bytes.HasPrefix(data, []byte("\x7fELF")) {
			return 0, shell.ErrUnhandled
		}
		env := make([]string, 0, len(in.Env))
		for k, v := range in.Env {
			env = append(env, k+"="+v)
		}
		sort.Strings(env)
		result, err := linux.Run(ctx, bytes.NewReader(data), linux.Config{Files: linux.GuestFiles{FS: files}, Umask: &in.Umask, Dir: in.Dir, Args: in.Args, Env: env, Stdin: in.Stdin, Stdout: in.Stdout, Stderr: in.Stderr, MaxInstructions: maximum})
		return result.Status, err
	}}, nil
}
func dateCommand(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var epoch int64
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "epoch", &epoch); err != nil {
		return nil, err
	}
	return &shell.Action{Name: "date", Run: func(ctx context.Context, in shell.Invocation) (int, error) {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		return shell.Date(in, func() time.Time { return time.Unix(epoch, 0) })
	}}, nil
}
func unameCommand(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs(b.Name(), args, kwargs); err != nil {
		return nil, err
	}
	return &shell.Action{Name: "uname", Run: func(ctx context.Context, in shell.Invocation) (int, error) {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		return shell.Uname(in)
	}}, nil
}
