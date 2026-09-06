package renvostar

import (
	"fmt"
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
		"go":   starlark.NewBuiltin("go", renvoGoBuiltin),
		"cc":   starlark.NewBuiltin("cc", renvoCCBuiltin),
		"make": starlark.NewBuiltin("make", renvoMakeBuiltin),
	}
}

func renvoGoBuiltin(
	_ *starlark.Thread,
	_ *starlark.Builtin,
	args starlark.Tuple,
	kwargs []starlark.Tuple,
) (starlark.Value, error) {
	var (
		source    *filesystem.Directory
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

// PathExists implements [driver.SourceFS].
func (s *sourceFs) PathExists(path string) bool {
	path = s.resolvePath(path)
	if slices.Contains(s.dir.Directories, path) {
		return true
	}
	if _, ok := s.dir.Files[path]; ok {
		return true
	}
	return false
}

// ReadDir implements [driver.SourceFS].
func (s *sourceFs) ReadDir(path string) ([]driver.DirEntry, bool) {
	path = s.resolvePath(path)

	// first check if path is a directory
	if !slices.Contains(s.dir.Directories, path) {
		return nil, false
	}

	// collect all entries in the directory
	entries := []driver.DirEntry{}
	for _, dir := range s.dir.Directories {
		if dir != path && gopath.Dir(dir) == path {
			entries = append(entries, driver.DirEntry{Name: gopath.Base(dir), IsDir: true})
		}
	}
	for file := range s.dir.Files {
		if gopath.Dir(file) == path {
			entries = append(entries, driver.DirEntry{Name: gopath.Base(file), IsDir: false})
		}
	}

	slices.SortFunc(entries, func(a, b driver.DirEntry) int { return strings.Compare(a.Name, b.Name) })
	return entries, true
}

// ReadFile implements [driver.SourceFS].
func (s *sourceFs) ReadFile(path string) ([]byte, bool) {
	path = s.resolvePath(path)

	f, ok := s.dir.Files[path]
	if !ok {
		return nil, false
	}

	if f.File != nil {
		data, err := starfile.ReadAll(f.File)
		if err != nil {
			if s.err == nil {
				s.err = fmt.Errorf("read %s: %w", path, err)
			}
			return nil, false
		}
		f.Data, f.File = data, nil
		s.dir.Files[path] = f
		return data, true
	}
	return f.Data, true
}

var (
	_ driver.SourceFS = &sourceFs{}
)

func compileModule(source *filesystem.Directory, input string, target string, arenaSize uint64) (*compiledModule, error) {
	snapshot := source.Snapshot()
	fs := &sourceFs{dir: snapshot}

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
