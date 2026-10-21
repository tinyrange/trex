package renvostar

import (
	"errors"
	"fmt"
	"io/fs"
	gopath "path"
	"slices"
	"strings"

	"github.com/tinyrange/trex/filesystem"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"

	"renvo.dev/driver"
)

func Builtins() starlark.StringDict {
	return starlark.StringDict{
		"compiler": starlark.NewBuiltin("compiler", commandBuiltin),
		"linker":   starlark.NewBuiltin("linker", commandBuiltin),
		"archiver": starlark.NewBuiltin("archiver", commandBuiltin),
		"headers":  starlark.NewBuiltin("headers", headersBuiltin),
		"go":       starlark.NewBuiltin("go", renvoGoBuiltin),
		"cc":       starlark.NewBuiltin("cc", renvoCCBuiltin),
		"make":     starlark.NewBuiltin("make", renvoMakeBuiltin),
	}
}

func renvoGoBuiltin(
	_ *starlark.Thread,
	_ *starlark.Builtin,
	args starlark.Tuple,
	kwargs []starlark.Tuple,
) (starlark.Value, error) {
	var (
		source    starlark.Value
		input     string
		target    string
		arenaSize uint64 = 32 * 1024 * 1024
	)

	if err := starlark.UnpackArgs(
		"go", args, kwargs,
		"source", &source,
		"input", &input,
		"target", &target,
		"arena_size?", &arenaSize,
	); err != nil {
		return nil, err
	}

	module, err := compileModule(source, input, target, arenaSize)
	if err != nil {
		return nil, err
	}
	return module, nil
}

type sourceFs struct {
	tree filesystem.Tree
	dir  filesystem.Snapshot
	err  error
	base string
}

func (s *sourceFs) resolvePath(path string) string {
	// Relative paths use the build's virtual working directory.
	if !strings.HasPrefix(path, "/") {
		path = gopath.Join("/", s.base, path)
	}
	return gopath.Clean(path)
}

// newSourceFS captures a stable project view without enumerating SCS trees.
func newSourceFS(source starlark.Value) (*sourceFs, error) {
	provider, ok := source.(filesystem.TreeSource)
	if !ok {
		return nil, fmt.Errorf("source: got %s, want a project tree", source.Type())
	}
	tree, err := provider.SnapshotTree()
	if err != nil {
		return nil, err
	}
	return &sourceFs{tree: tree, dir: filesystem.Snapshot{Files: map[string]filesystem.FileRecord{}}}, nil
}
func (s *sourceFs) recordError(err error) {
	if err != nil && !errors.Is(err, fs.ErrNotExist) && s.err == nil {
		s.err = err
	}
}
func (s *sourceFs) PathExists(name string) bool {
	name = s.resolvePath(name)
	if slices.Contains(s.dir.Directories, name) {
		return true
	}
	if _, ok := s.dir.Files[name]; ok {
		return true
	}
	if s.tree != nil {
		_, err := s.tree.Lookup(strings.TrimPrefix(name, "/"))
		s.recordError(err)
		return err == nil
	}
	return false
}
func (s *sourceFs) ReadDir(name string) ([]driver.DirEntry, bool) {
	name = s.resolvePath(name)
	entries := map[string]driver.DirEntry{}
	exists := slices.Contains(s.dir.Directories, name)
	if s.tree != nil {
		info, err := s.tree.Lookup(strings.TrimPrefix(name, "/"))
		s.recordError(err)
		if err == nil && info.Kind == "dir" {
			base, err := s.tree.ReadDir(strings.TrimPrefix(name, "/"))
			s.recordError(err)
			if err != nil {
				return nil, false
			}
			exists = true
			for _, e := range base {
				entries[e.Name] = driver.DirEntry{Name: e.Name, IsDir: e.Kind == "dir"}
			}
		}
	}
	if !exists {
		return nil, false
	}
	for _, dir := range s.dir.Directories {
		if dir != name && gopath.Dir(dir) == name {
			child := gopath.Base(dir)
			entries[child] = driver.DirEntry{Name: child, IsDir: true}
		}
	}
	for file := range s.dir.Files {
		if gopath.Dir(file) == name {
			child := gopath.Base(file)
			entries[child] = driver.DirEntry{Name: child}
		}
	}
	out := make([]driver.DirEntry, 0, len(entries))
	for _, e := range entries {
		out = append(out, e)
	}
	slices.SortFunc(out, func(a, b driver.DirEntry) int { return strings.Compare(a.Name, b.Name) })
	return out, true
}
func (s *sourceFs) ReadFile(name string) ([]byte, bool) {
	name = s.resolvePath(name)
	if file, ok := s.dir.Files[name]; ok {
		if file.File == nil {
			return file.Data, true
		}
		data, err := starfile.ReadAll(file.File)
		s.recordError(err)
		if err != nil {
			return nil, false
		}
		file.Data, file.File = data, nil
		s.dir.Files[name] = file
		return data, true
	}
	if s.tree == nil {
		return nil, false
	}
	info, err := s.tree.Lookup(strings.TrimPrefix(name, "/"))
	s.recordError(err)
	if err != nil || info.Kind != "file" {
		return nil, false
	}
	file, err := s.tree.OpenFile(strings.TrimPrefix(name, "/"))
	s.recordError(err)
	if err != nil {
		return nil, false
	}
	data, err := starfile.ReadAll(file)
	s.recordError(err)
	if err != nil {
		return nil, false
	}
	s.dir.Files[name] = filesystem.FileRecord{Data: data, Size: int64(len(data))}
	return data, true
}

var (
	_ driver.SourceFS = &sourceFs{}
)

func compileModule(source starlark.Value, input string, target string, arenaSize uint64) (*compiledModule, error) {
	fs, err := newSourceFS(source)
	if err != nil {
		return nil, err
	}

	result, err := driver.Compile(&driver.Request{
		Input:      []string{input},
		Filesystem: fs,
		Target:     target,
		ArenaSize:  arenaSize,
	})
	if err != nil {
		return nil, err
	}
	if fs.err != nil {
		return nil, fs.err
	}

	return &compiledModule{
		result: result,
	}, nil
}

type compiledModule struct {
	result  *driver.Result
	outputs map[string][]byte
}

func (m *compiledModule) Attr(name string) (starlark.Value, error) {
	switch name {
	case "outputs":
		dict := starlark.NewDict(len(m.outputs))
		names := make([]string, 0, len(m.outputs))
		for name := range m.outputs {
			names = append(names, name)
		}
		slices.Sort(names)
		for _, name := range names {
			if err := dict.SetKey(starlark.String(name), starlark.Bytes(m.outputs[name])); err != nil {
				return nil, err
			}
		}
		dict.Freeze()
		return dict, nil
	case "ok":
		return starlark.Bool(m.result.Ok), nil
	case "diagnostic":
		return starlark.String(fmt.Sprintf("%+v", m.result.Diagnostic)), nil
	case "binary":
		return starlark.Bytes(m.result.Binary), nil
	default:
		return nil, nil
	}
}

func (m *compiledModule) AttrNames() []string {
	return []string{"ok", "diagnostic", "binary", "outputs"}
}

func (m *compiledModule) String() string       { return "compiledModule" }
func (m *compiledModule) Type() string         { return "compiledModule" }
func (m *compiledModule) Freeze()              {}
func (m *compiledModule) Truth() starlark.Bool { return starlark.True }
func (m *compiledModule) Hash() (uint32, error) {
	return 0, fmt.Errorf("unimplemented")
}

var (
	_ starlark.Value    = &compiledModule{}
	_ starlark.HasAttrs = &compiledModule{}
)
