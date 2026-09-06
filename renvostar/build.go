package renvostar

import (
	"fmt"
	"path"
	"slices"

	"github.com/tinyrange/trex/filesystem"
	"go.starlark.net/starlark"
	"renvo.dev/driver"
)

func stringList(value starlark.Value, name string) ([]string, error) {
	var values []starlark.Value
	switch v := value.(type) {
	case starlark.Tuple:
		values = []starlark.Value(v)
	case *starlark.List:
		for i := 0; i < v.Len(); i++ {
			values = append(values, v.Index(i))
		}
	default:
		return nil, fmt.Errorf("%s: want list or tuple of strings, got %s", name, value.Type())
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		s, ok := starlark.AsString(value)
		if !ok {
			return nil, fmt.Errorf("%s: want string, got %s", name, value.Type())
		}
		result = append(result, s)
	}
	return result, nil
}

func renvoCCBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var source *filesystem.Directory
	var input starlark.Value
	var target string
	var flags starlark.Value = starlark.Tuple{}
	arenaSize := uint64(32 << 20)
	if err := starlark.UnpackArgs("cc", args, kwargs, "source", &source, "input", &input, "target", &target, "flags?", &flags, "arena_size?", &arenaSize); err != nil {
		return nil, err
	}
	if target == "" {
		return nil, fmt.Errorf("cc: target must be specified")
	}
	inputs := []string{}
	if name, ok := starlark.AsString(input); ok {
		inputs = append(inputs, name)
	} else {
		var err error
		inputs, err = stringList(input, "input")
		if err != nil {
			return nil, err
		}
	}
	if len(inputs) == 0 {
		return nil, fmt.Errorf("cc: at least one input is required")
	}
	options, err := stringList(flags, "flags")
	if err != nil {
		return nil, err
	}
	command := append([]string{"cc"}, options...)
	command = append(command, inputs...)
	fs := &sourceFs{dir: source.Snapshot()}
	result, err := driver.CompileCommand(&driver.CommandRequest{Filesystem: fs, Args: command, Target: target, ArenaSize: arenaSize})
	if fs.err != nil {
		return nil, fs.err
	}
	if err != nil {
		return nil, err
	}
	return &compiledModule{result: &result.Result, outputs: result.Outputs}, nil
}

func renvoMakeBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var source *filesystem.Directory
	input := "Makefile"
	var target, output string
	var targets starlark.Value = starlark.Tuple{}
	arenaSize := uint64(32 << 20)
	if err := starlark.UnpackArgs("make", args, kwargs, "source", &source, "target", &target, "input?", &input, "targets?", &targets, "output?", &output, "arena_size?", &arenaSize); err != nil {
		return nil, err
	}
	if target == "" {
		return nil, fmt.Errorf("make: target must be specified")
	}
	goals, err := stringList(targets, "targets")
	if err != nil {
		return nil, err
	}
	fs := &sourceFs{dir: source.Snapshot()}
	makepath := fs.resolvePath(input)
	contents, ok := fs.ReadFile(makepath)
	if fs.err != nil {
		return nil, fs.err
	}
	if !ok {
		return nil, fmt.Errorf("make: could not read %s", input)
	}
	fs.base = path.Dir(makepath)
	commands, err := driver.PlanMake(contents, goals, fs.PathExists)
	if err != nil {
		return nil, err
	}
	module := &compiledModule{result: &driver.Result{Ok: true}, outputs: map[string][]byte{}}
	for _, command := range commands {
		result, err := driver.CompileCommand(&driver.CommandRequest{Filesystem: fs, Args: command.Args[1:], Target: target, ArenaSize: arenaSize})
		if fs.err != nil {
			return nil, fs.err
		}
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", input, command.Line, err)
		}
		module.result = &result.Result
		if !result.Ok {
			return module, nil
		}
		names := make([]string, 0, len(result.Outputs))
		for name := range result.Outputs {
			names = append(names, name)
		}
		slices.Sort(names)
		for _, name := range names {
			if name == "-" {
				continue
			}
			data := result.Outputs[name]
			if err := fs.write(name, data); err != nil {
				return nil, fmt.Errorf("%s:%d: %w", input, command.Line, err)
			}
			module.outputs[path.Clean(name)] = data
		}
	}
	if output != "" {
		data, ok := fs.ReadFile(output)
		if fs.err != nil {
			return nil, fs.err
		}
		if !ok {
			return nil, fmt.Errorf("make: output %s was not produced", output)
		}
		module.result.Binary = data
	}
	return module, nil
}

func (s *sourceFs) write(name string, data []byte) error {
	name = s.resolvePath(name)
	if slices.Contains(s.dir.Directories, name) {
		return fmt.Errorf("output %s is a directory", name)
	}
	for dir := path.Dir(name); ; dir = path.Dir(dir) {
		if _, ok := s.dir.Files[dir]; ok {
			return fmt.Errorf("output parent %s is a file", dir)
		}
		if dir == "/" {
			break
		}
	}
	s.dir.Files[name] = filesystem.FileRecord{Data: data, Size: int64(len(data))}
	for dir := path.Dir(name); !s.PathExists(dir); dir = path.Dir(dir) {
		s.dir.Directories = append(s.dir.Directories, dir)
	}
	return nil
}
