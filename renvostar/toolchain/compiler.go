// Package toolchain implements in-process compiler command adapters. It does not
// install tools, select commands, download sources, or orchestrate builds.
package toolchain

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"

	"github.com/tinyrange/trex/emulator/shell"
	"renvo.dev/driver"
)

type Executor struct {
	FS        *shell.MemoryFS
	Target    string
	ArenaSize uint64
}

func resolve(dir, name string) string {
	if path.IsAbs(name) {
		return path.Clean(name)
	}
	return path.Join(dir, name)
}
func (e *Executor) toolchain(in shell.Invocation, link bool) (int, error) {
	source := &sourceFS{fs: e.FS, dir: in.Dir}
	// Read stdin only when the command asks for it; configure often inherits an
	// otherwise-open input stream, which must not make compilation block.
	var stdin []byte
	for _, arg := range in.Args[1:] {
		if !link && arg == "-" {
			var err error
			stdin, err = io.ReadAll(io.LimitReader(in.Stdin, (8<<20)+1))
			if err != nil {
				return 0, err
			}
			if len(stdin) > 8<<20 {
				return 0, fmt.Errorf("toolchain: compiler stdin budget exceeded")
			}
			break
		}
	}
	request := &driver.CommandRequest{Filesystem: source, Args: in.Args[1:], Target: e.Target, ArenaSize: e.ArenaSize, Stdin: stdin}
	var result *driver.CommandResult
	var err error
	if link {
		result, err = driver.LinkCommand(request)
	} else {
		request.Args = append([]string{"cc"}, request.Args...)
		result, err = driver.CompileCommand(request)
	}
	if source.err != nil {
		return 0, source.err
	}
	if err != nil {
		return 0, err
	}
	if !result.Ok {
		_, err = fmt.Fprintf(in.Stderr, "%s:%d: %s: %s\n", result.Diagnostic.Path, result.Diagnostic.Line, result.Diagnostic.Code, result.Diagnostic.Message)
		return 1, err
	}
	for name, data := range result.Outputs {
		if name == "-" {
			if _, err := in.Stdout.Write(data); err != nil {
				return 0, err
			}
			continue
		}
		mode := fs.FileMode(0666)
		if bytes.HasPrefix(data, []byte("\x7fELF")) && len(data) > 18 && data[16] != 1 {
			mode = 0777
		}
		output, err := e.FS.OpenMode(resolve(in.Dir, name), shell.Write|shell.Create|shell.Truncate, mode&^in.Umask)
		if err != nil {
			return 0, err
		}
		_, writeErr := io.Copy(output, bytes.NewReader(data))
		closeErr := output.Close()
		if writeErr != nil {
			return 0, writeErr
		}
		if closeErr != nil {
			return 0, closeErr
		}
	}
	return 0, nil
}

type sourceFS struct {
	fs  shell.FileSystem
	dir string
	err error
}

func (s *sourceFS) remember(err error) {
	if err != nil && !errors.Is(err, fs.ErrNotExist) && s.err == nil {
		s.err = err
	}
}
func (s *sourceFS) PathExists(name string) bool {
	_, err := s.fs.Stat(resolve(s.dir, name))
	s.remember(err)
	return err == nil
}
func (s *sourceFS) ReadDir(name string) ([]driver.DirEntry, bool) {
	entries, err := s.fs.ReadDir(resolve(s.dir, name))
	if err != nil {
		s.remember(err)
		return nil, false
	}
	result := make([]driver.DirEntry, len(entries))
	for i, entry := range entries {
		result[i] = driver.DirEntry{Name: entry.Name(), IsDir: entry.IsDir()}
	}
	return result, true
}
func (s *sourceFS) ReadFile(name string) ([]byte, bool) {
	f, err := s.fs.Open(resolve(s.dir, name), shell.Read)
	if err != nil {
		s.remember(err)
		return nil, false
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, (16<<20)+1))
	if len(data) > 16<<20 {
		err = fmt.Errorf("toolchain: source file budget exceeded")
	}
	s.remember(err)
	return data, err == nil
}
