package buildenv

import (
	"fmt"
	"github.com/tinyrange/trex/emulator/shell"
	"renvo.dev/driver"
)

func (e *Environment) archive(in shell.Invocation, index bool) (int, error) {
	args := in.Args[1:]
	if index {
		if len(args) != 1 {
			return 1, nil
		}
		args = append([]string{"s"}, args...)
	}
	source := &sourceFS{fs: e.FS, dir: in.Dir}
	r, err := driver.ArchiveCommand(&driver.CommandRequest{Filesystem: source, Args: args})
	if source.err != nil {
		return 0, source.err
	}
	if err != nil {
		return 0, err
	}
	if !r.Ok {
		_, err = fmt.Fprintln(in.Stderr, r.Diagnostic.Message)
		return 1, err
	}
	f, err := e.FS.OpenMode(resolve(in.Dir, r.Output), shell.Write|shell.Create|shell.Truncate, 0666&^in.Umask)
	if err != nil {
		return 0, err
	}
	_, err = f.Write(r.Binary)
	closeErr := f.Close()
	if err != nil {
		return 0, err
	}
	return 0, closeErr
}
