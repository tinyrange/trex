// Package native adapts host filesystems to trex's portable filesystem values.
package native

import (
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

// hostFilesystem is an explicitly native backend. Scripts see the same
// mapping-and-directory interface as parsed filesystems, while OS paths stay
// confined to this adapter.
type hostFilesystem struct {
	root    string
	entries map[string]hostFilesystemEntry
	paths   []string
}

type hostFilesystemEntry struct {
	name     string
	fullPath string
	size     int64
	dir      bool
	children []string
}

func HostBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var root string
	if err := starlark.UnpackArgs("filesystem.host", args, kwargs, "root", &root); err != nil {
		return nil, err
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(abs)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("filesystem.host: %s is not a directory", root)
	}
	fs := &hostFilesystem{root: abs, entries: make(map[string]hostFilesystemEntry)}
	fs.entries["/"] = hostFilesystemEntry{name: "/", fullPath: abs, dir: true}
	err = filepath.WalkDir(abs, func(name string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if name == abs {
			return nil
		}
		relative, err := filepath.Rel(abs, name)
		if err != nil {
			return err
		}
		logical := path.Clean("/" + filepath.ToSlash(relative))
		info, err := entry.Info()
		if err != nil {
			return err
		}
		fs.entries[strings.ToLower(logical)] = hostFilesystemEntry{
			name: logical, fullPath: name, size: info.Size(), dir: entry.IsDir(),
		}
		fs.paths = append(fs.paths, logical)
		parent := strings.ToLower(path.Dir(logical))
		parentEntry := fs.entries[parent]
		parentEntry.children = append(parentEntry.children, logical)
		fs.entries[parent] = parentEntry
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(fs.paths, func(i, j int) bool { return strings.ToLower(fs.paths[i]) < strings.ToLower(fs.paths[j]) })
	for key, entry := range fs.entries {
		sort.Slice(entry.children, func(i, j int) bool { return strings.ToLower(entry.children[i]) < strings.ToLower(entry.children[j]) })
		fs.entries[key] = entry
	}
	return fs, nil
}

func (f *hostFilesystem) String() string       { return fmt.Sprintf("<host filesystem %q>", f.root) }
func (f *hostFilesystem) Type() string         { return "host_filesystem" }
func (f *hostFilesystem) Freeze()              {}
func (f *hostFilesystem) Truth() starlark.Bool { return starlark.True }
func (f *hostFilesystem) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", f.Type())
}
func (f *hostFilesystem) AttrNames() []string { return []string{"files", "find"} }
func (f *hostFilesystem) Attr(name string) (starlark.Value, error) {
	switch name {
	case "files":
		values := make([]starlark.Value, len(f.paths))
		for index, name := range f.paths {
			values[index] = starlark.String(name)
		}
		return starlark.NewList(values), nil
	case "find":
		return starlark.NewBuiltin("host_filesystem.find", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var name string
			if err := starlark.UnpackArgs("host_filesystem.find", args, kwargs, "path", &name); err != nil {
				return nil, err
			}
			value, found, err := f.Get(starlark.String(name))
			if err != nil || !found {
				return starlark.None, err
			}
			return value, nil
		}), nil
	default:
		return nil, nil
	}
}
func (f *hostFilesystem) Get(key starlark.Value) (starlark.Value, bool, error) {
	name, ok := starlark.AsString(key)
	if !ok {
		return nil, false, nil
	}
	logical := path.Clean("/" + strings.TrimPrefix(strings.ReplaceAll(name, "\\", "/"), "/"))
	entry, ok := f.entries[strings.ToLower(logical)]
	if !ok {
		return nil, false, nil
	}
	if entry.dir {
		return &hostDirectory{filesystem: f, name: entry.name}, true, nil
	}
	return &hostReadFile{name: entry.fullPath, size: entry.size}, true, nil
}

type hostReadFile struct {
	name string
	size int64
}

func (f *hostReadFile) ReadAt(buffer []byte, offset int64) (int, error) {
	file, err := os.Open(f.name)
	if err != nil {
		return 0, err
	}
	defer file.Close()
	return file.ReadAt(buffer, offset)
}
func (f *hostReadFile) WriteAt([]byte, int64) (int, error) {
	return 0, fmt.Errorf("%s is read-only", f.name)
}
func (f *hostReadFile) Size() int64                              { return f.size }
func (f *hostReadFile) String() string                           { return fmt.Sprintf("<file %q>", f.name) }
func (*hostReadFile) Type() string                               { return "file" }
func (*hostReadFile) Freeze()                                    {}
func (*hostReadFile) Truth() starlark.Bool                       { return starlark.True }
func (*hostReadFile) Hash() (uint32, error)                      { return 0, fmt.Errorf("unhashable: file") }
func (f *hostReadFile) Attr(name string) (starlark.Value, error) { return starfile.Attr(f, name), nil }
func (*hostReadFile) AttrNames() []string                        { return starfile.AttrNames() }

var _ io.ReaderAt = (*hostReadFile)(nil)

type hostDirectory struct {
	filesystem *hostFilesystem
	name       string
}

func (d *hostDirectory) String() string       { return fmt.Sprintf("<host directory %q>", d.name) }
func (d *hostDirectory) Type() string         { return "directory" }
func (d *hostDirectory) Freeze()              {}
func (d *hostDirectory) Truth() starlark.Bool { return starlark.True }
func (d *hostDirectory) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", d.Type())
}
func (d *hostDirectory) AttrNames() []string { return []string{"files"} }
func (d *hostDirectory) Attr(name string) (starlark.Value, error) {
	if name != "files" {
		return nil, nil
	}
	entry := d.filesystem.entries[strings.ToLower(d.name)]
	values := make([]starlark.Value, len(entry.children))
	for index, child := range entry.children {
		values[index] = starlark.String(child)
	}
	return starlark.NewList(values), nil
}
