package renvostar

import (
	"fmt"
	gopath "path"
	"slices"
	"strings"

	"github.com/tinyrange/trex/filesystem"
	"go.starlark.net/starlark"

	"renvo.dev/driver"
)

func Builtins() starlark.StringDict {
	return starlark.StringDict{
		"go": starlark.NewBuiltin("go", renvoGoBuiltin),
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
	dir filesystem.Snapshot
}

func (s *sourceFs) resolvePath(path string) string {
	// if path is relative, resolve it against the root of the snapshot which is /
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return path
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
		if strings.HasPrefix(dir, path) {
			entries = append(entries, driver.DirEntry{Name: gopath.Base(dir), IsDir: true})
		}
	}
	for file := range s.dir.Files {
		if strings.HasPrefix(file, path) {
			entries = append(entries, driver.DirEntry{Name: gopath.Base(file), IsDir: false})
		}
	}

	return entries, true
}

// ReadFile implements [driver.SourceFS].
func (s *sourceFs) ReadFile(path string) ([]byte, bool) {
	path = s.resolvePath(path)

	f, ok := s.dir.Files[path]
	if !ok {
		return nil, false
	}

	return f.Data, true
}

var (
	_ driver.SourceFS = &sourceFs{}
)

func compileModule(source *filesystem.Directory, input string, target string, arenaSize uint64) (*compiledModule, error) {
	snapshot := source.Snapshot()

	result, err := driver.Compile(&driver.Request{
		Input:      []string{input},
		Filesystem: &sourceFs{dir: snapshot},
		Target:     target,
		ArenaSize:  arenaSize,
	})
	if err != nil {
		return nil, err
	}

	return &compiledModule{
		result: result,
	}, nil
}

type compiledModule struct {
	result *driver.Result
}

func (m *compiledModule) Attr(name string) (starlark.Value, error) {
	switch name {
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
	return []string{"ok", "diagnostic", "binary"}
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
