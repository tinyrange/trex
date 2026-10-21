package toolchain

import (
	"bytes"
	"context"
	"sort"

	"github.com/tinyrange/trex/emulator/linux"
	"github.com/tinyrange/trex/emulator/shell"
	"renvo.dev/driver"
)

// Low-level compiler regressions use only these four commands. The complete
// installation and workload are tested through the real Starlark recipe.
type testEnvironment struct{ Command shell.CommandHandler }

func New(files *shell.MemoryFS) (*testEnvironment, error) {
	if err := files.Mkdir("/bin"); err != nil {
		return nil, err
	}
	if err := files.Mkdir("/tmp"); err != nil {
		return nil, err
	}
	commands := map[string]*shell.Action{
		"/bin/cc": Compiler("linux/amd64", 32<<20, false),
		"/bin/ld": Compiler("linux/amd64", 32<<20, true),
		"/bin/ar": Archiver(false), "/bin/ranlib": Archiver(true),
	}
	for name := range commands {
		if err := files.WriteFile(name, nil, 0755); err != nil {
			return nil, err
		}
	}
	if bundled := driver.BundledSourceFS(); bundled != nil && bundled.PathExists("/libc/include") {
		if err := installHeaders(files, bundled, "/libc/include"); err != nil {
			return nil, err
		}
	}
	elf := &shell.Action{Name: "test ELF", Run: func(ctx context.Context, in shell.Invocation) (int, error) {
		image, err := files.ReadFile(in.Executable)
		if err != nil {
			return 0, err
		}
		if !bytes.HasPrefix(image, []byte("\x7fELF")) {
			return 0, shell.ErrUnhandled
		}
		env := []string{}
		for k, v := range in.Env {
			env = append(env, k+"="+v)
		}
		sort.Strings(env)
		result, err := linux.Run(ctx, bytes.NewReader(image), linux.Config{Files: linux.GuestFiles{FS: files}, Dir: in.Dir, Args: in.Args, Env: env, Umask: &in.Umask, Stdin: in.Stdin, Stdout: in.Stdout, Stderr: in.Stderr, MaxInstructions: 10000000})
		return result.Status, err
	}}
	return &testEnvironment{Command: shell.Commands(commands, elf)}, nil
}
