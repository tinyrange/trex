// Package buildenv connects the shell's virtual command boundary to Renvo and
// the Linux/amd64 interpreter. It never invokes a host compiler or linker.
package buildenv

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/tinyrange/trex/emulator/linux"
	"github.com/tinyrange/trex/emulator/shell"
	"renvo.dev/driver"
)

const compilerImage = "trex virtual executable: renvo cc\n"
const linkerImage = "trex virtual executable: renvo ld\n"
const arImage = "trex virtual executable: ar\n"
const ranlibImage = "trex virtual executable: ranlib\n"
const dateImage = "trex virtual executable: date\n"
const unameImage = "trex virtual executable: uname\n"

// Environment owns no host resources. FS is shared by shell commands, the
// compiler and generated outputs. Compile/run limits are explicit and bounded.
type Environment struct {
	FS *shell.MemoryFS
	// Now supplies the virtual wall clock. Nil uses time.Now, interpreted in UTC.
	Now             func() time.Time
	ArenaSize       uint64
	MaxInstructions uint64
}

func New(files *shell.MemoryFS) (*Environment, error) {
	if files == nil {
		return nil, fmt.Errorf("buildenv: virtual filesystem is required")
	}
	for _, dir := range []string{"/bin", "/tmp"} {
		if err := files.Mkdir(dir); err != nil && !errors.Is(err, fs.ErrExist) {
			return nil, err
		}
		if st, err := files.Stat(dir); err != nil || !st.IsDir() {
			return nil, fmt.Errorf("buildenv: %s must be a directory", dir)
		}
	}
	programs := map[string]string{"cc": compilerImage, "ld": linkerImage, "uname": unameImage, "date": dateImage, "ar": arImage, "ranlib": ranlibImage}
	for _, name := range []string{"sh", "cat", "mkdir", "rm", "rmdir", "basename", "dirname", "expr", "ls", "sed", "grep", "egrep", "fgrep", "cp", "mv", "sleep", "diff", "tr", "sort", "touch", "chmod", "awk", "uniq", "wc", "make"} {
		programs[name] = "#!/bin/sh\nexec " + name + " \"$@\"\n"
	}
	for name, source := range programs {
		filename := "/bin/" + name
		if _, err := files.Stat(filename); err == nil {
			return nil, fmt.Errorf("buildenv: refusing to replace %s", filename)
		} else if !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		if err := files.WriteFile(filename, []byte(source), 0755); err != nil {
			return nil, err
		}
	}
	// Dependency files name bundled headers by their virtual absolute paths.
	// Make must observe those same files on later invocations, not a compiler-
	// private filesystem overlay that disappears after each command.
	if bundled := driver.BundledSourceFS(); bundled != nil && bundled.PathExists("/libc/include") {
		if err := installHeaders(files, bundled, "/libc/include"); err != nil {
			return nil, err
		}
	}
	return &Environment{FS: files, ArenaSize: 32 << 20, MaxInstructions: 10000000}, nil
}
func resolve(dir, name string) string {
	if path.IsAbs(name) {
		return path.Clean(name)
	}
	return path.Join(dir, name)
}
func (e *Environment) Command(ctx context.Context, in shell.Invocation) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if len(in.Args) == 0 {
		return 0, fmt.Errorf("buildenv: empty command")
	}
	names := []string{resolve(in.Dir, in.Args[0])}
	if !strings.Contains(in.Args[0], "/") {
		names = nil
		for _, dir := range strings.Split(in.Env["PATH"], ":") {
			names = append(names, resolve(in.Dir, path.Join(dir, in.Args[0])))
		}
	}
	for _, name := range names {
		st, err := e.FS.Stat(name)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return 0, err
		}
		if st.IsDir() || st.Mode().Perm()&0111 == 0 {
			continue
		}
		data, err := e.FS.ReadFile(name)
		if err != nil {
			return 0, err
		}
		if string(data) == dateImage {
			return e.date(in)
		}
		if string(data) == unameImage {
			return uname(in)
		}
		if string(data) == arImage || string(data) == ranlibImage {
			return e.archive(in, string(data) == ranlibImage)
		}
		if string(data) == compilerImage || string(data) == linkerImage {
			return e.toolchain(in, string(data) == linkerImage)
		}
		if bytes.HasPrefix(data, []byte("\x7fELF")) {
			env := make([]string, 0, len(in.Env))
			for k, v := range in.Env {
				env = append(env, k+"="+v)
			}
			sort.Strings(env)
			result, err := linux.Run(ctx, bytes.NewReader(data), linux.Config{Files: guestFiles{e.FS}, Umask: &in.Umask, Dir: in.Dir, Args: in.Args, Env: env, Stdin: in.Stdin, Stdout: in.Stdout, Stderr: in.Stderr, MaxInstructions: e.MaxInstructions})
			return result.Status, err
		}
		return 0, shell.ErrUnhandled
	}
	return 0, shell.ErrUnhandled
}
func (e *Environment) toolchain(in shell.Invocation, link bool) (int, error) {
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
				return 0, fmt.Errorf("buildenv: compiler stdin budget exceeded")
			}
			break
		}
	}
	request := &driver.CommandRequest{Filesystem: source, Args: in.Args[1:], Target: "linux/amd64", ArenaSize: e.ArenaSize, Stdin: stdin}
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
		err = fmt.Errorf("buildenv: source file budget exceeded")
	}
	s.remember(err)
	return data, err == nil
}
