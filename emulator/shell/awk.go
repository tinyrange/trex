package shell

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"strings"
	"time"

	"github.com/benhoyt/goawk/interp"
	"github.com/benhoyt/goawk/parser"
	"github.com/tinyrange/trex/channel"
)

// AWK files are resolved by the same virtual filesystem as shell redirections.
// Supplying all I/O and ENVIRON and setting NoExec are mandatory: nil GoAWK
// configuration fields would otherwise enable host resources.
type awkFS struct{ s *shell }
type awkFile struct {
	channel.ByteChannel
	files FileSystem
	name  string
}

func (f *awkFile) Stat() (fs.FileInfo, error) { return f.files.Stat(f.name) }
func (f awkFS) Open(name string) (fs.File, error) {
	name = f.s.resolve(name)
	ch, e := f.s.cfg.FS.Open(name, Read)
	if e != nil {
		return nil, e
	}
	return &awkFile{ch, f.s.cfg.FS, name}, nil
}
func (f awkFS) Create(name string) (io.WriteCloser, error) {
	return f.s.open(f.s.resolve(name), Write|Create|Truncate, 0666)
}
func (f awkFS) Append(name string) (io.WriteCloser, error) {
	return f.s.open(f.s.resolve(name), Write|Create|Append, 0666)
}

func (s *shell) awk(args []string) error {
	var programs []string
	vars := []string{}
	for len(args) > 0 && strings.HasPrefix(args[0], "-") && args[0] != "-" {
		arg := args[0]
		args = args[1:]
		if arg == "--" {
			break
		}
		flag, value := arg, ""
		if len(arg) > 2 && (arg[:2] == "-F" || arg[:2] == "-v" || arg[:2] == "-f") {
			flag, value = arg[:2], arg[2:]
		}
		if flag != "-F" && flag != "-v" && flag != "-f" {
			return unsupported("awk option " + arg)
		}
		if value == "" {
			if len(args) == 0 {
				return s.diagnostic(fmt.Errorf("awk: %s requires an argument", flag))
			}
			value = args[0]
			args = args[1:]
		}
		switch flag {
		case "-F":
			vars = append(vars, "FS", value)
		case "-v":
			name, val, ok := strings.Cut(value, "=")
			if !ok || !validName(name) {
				return s.diagnostic(fmt.Errorf("awk: invalid variable assignment"))
			}
			vars = append(vars, name, val)
		case "-f":
			data, e := s.readFile(s.resolve(value))
			if e != nil {
				return s.diagnostic(e)
			}
			programs = append(programs, string(data))
		}
	}
	if len(programs) == 0 {
		if len(args) == 0 {
			return s.diagnostic(fmt.Errorf("awk: program required"))
		}
		programs = append(programs, args[0])
		args = args[1:]
	}
	source := strings.Join(programs, "\n")
	if len(source) > s.cfg.MaxSubstitutionBytes {
		return fmt.Errorf("awk: source budget exceeded")
	}
	program, err := parser.ParseProgram([]byte(source), nil)
	if err != nil {
		return s.diagnostic(fmt.Errorf("awk: %w", err))
	}
	machine, err := interp.New(program)
	if err != nil {
		return err
	}
	environment := []string{}
	for name, v := range s.vars {
		if v.Exported && v.IsSet() {
			environment = append(environment, name, v.String())
		}
	}
	timeout := s.cfg.MaxAWKTime
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(s.ctx, timeout)
	defer cancel()
	status, err := machine.ExecuteContext(ctx, &interp.Config{Stdin: s.input(), Output: s.output(1), Error: s.output(2), Argv0: "awk", Args: args, Vars: vars, Environ: environment, FileSystem: awkFS{s}, NoExec: true, Chars: false})
	s.status = status & 255
	if err != nil {
		return fmt.Errorf("awk: %w", err)
	}
	return nil
}
