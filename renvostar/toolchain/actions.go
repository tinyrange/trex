package toolchain

import (
	"context"
	"fmt"

	"github.com/tinyrange/trex/emulator/shell"
)

// Compiler creates a compiler/linker capability, not an installed executable.
func Compiler(target string, arena uint64, link bool) *shell.Action {
	name := "renvo.cc"
	if link {
		name = "renvo.ld"
	}
	return &shell.Action{Name: name, Run: func(ctx context.Context, in shell.Invocation) (int, error) {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		files, ok := in.FS.(*shell.MemoryFS)
		if !ok {
			return 0, fmt.Errorf("%s: expected Unix filesystem", name)
		}
		return (&Executor{FS: files, Target: target, ArenaSize: arena}).toolchain(in, link)
	}}
}
func Archiver(index bool) *shell.Action {
	return &shell.Action{Name: "renvo.ar", Run: func(ctx context.Context, in shell.Invocation) (int, error) {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		files, ok := in.FS.(*shell.MemoryFS)
		if !ok {
			return 0, fmt.Errorf("renvo.ar: expected Unix filesystem")
		}
		return (&Executor{FS: files}).archive(in, index)
	}}
}
