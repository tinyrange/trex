package native

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/tinyrange/trex/lifecycle"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

// lazyHost uses a rooted native backend and lists only the requested directory.
// Symlinks are not followed; all opens remain confined even if paths are renamed.
type lazyHost struct{ root *os.Root }

func newLazyHost(thread *starlark.Thread, name string) (starlark.Value, error) {
	root, err := os.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	h := &lazyHost{root: root}
	if thread != nil {
		if resources, err := lifecycle.ForThread(thread); err == nil {
			if _, err := resources.Add(h); err != nil {
				root.Close()
				return nil, err
			}
		}
	}
	return h, nil
}
func (h *lazyHost) Close() error        { return h.root.Close() }
func (*lazyHost) String() string        { return "<host filesystem>" }
func (*lazyHost) Type() string          { return "host_filesystem" }
func (*lazyHost) Freeze()               {}
func (*lazyHost) Truth() starlark.Bool  { return starlark.True }
func (*lazyHost) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable filesystem") }
func (h *lazyHost) Get(key starlark.Value) (starlark.Value, bool, error) {
	name, ok := starlark.AsString(key)
	if !ok {
		return nil, false, fs.ErrInvalid
	}
	if strings.ContainsAny(name, "\\\x00") {
		return nil, false, fs.ErrInvalid
	}
	for _, part := range strings.Split(name, "/") {
		if part == ".." {
			return nil, false, fs.ErrInvalid
		}
	}
	relative := strings.Trim(name, "/")
	if relative == "" {
		relative = "."
	}
	info, err := h.root.Lstat(relative)
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		return nil, false, nil
	}
	if info.IsDir() {
		return &lazyHostDirectory{h, relative}, true, nil
	}
	if !info.Mode().IsRegular() {
		return nil, false, nil
	}
	return &lazyHostFile{host: h, name: relative, size: info.Size()}, true, nil
}

type lazyHostDirectory struct {
	host *lazyHost
	name string
}

func (*lazyHostDirectory) String() string        { return "<host directory>" }
func (*lazyHostDirectory) Type() string          { return "directory" }
func (*lazyHostDirectory) Freeze()               {}
func (*lazyHostDirectory) Truth() starlark.Bool  { return starlark.True }
func (*lazyHostDirectory) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable directory") }
func (*lazyHostDirectory) AttrNames() []string   { return []string{"files"} }
func (d *lazyHostDirectory) Attr(name string) (starlark.Value, error) {
	if name != "files" {
		return nil, nil
	}
	f, err := d.host.root.Open(d.name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	entries, err := f.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	values := make([]starlark.Value, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || entry.Type().IsRegular() {
			values = append(values, starlark.String(path.Join("/", d.name, entry.Name())))
		}
	}
	return starlark.NewList(values), nil
}

type lazyHostFile struct {
	host *lazyHost
	name string
	size int64
}

func (f *lazyHostFile) ReadAt(p []byte, off int64) (int, error) {
	file, err := f.host.root.Open(f.name)
	if err != nil {
		return 0, err
	}
	defer file.Close()
	return file.ReadAt(p, off)
}
func (*lazyHostFile) WriteAt([]byte, int64) (int, error)         { return 0, fs.ErrPermission }
func (f *lazyHostFile) Size() int64                              { return f.size }
func (*lazyHostFile) String() string                             { return "<host file>" }
func (*lazyHostFile) Type() string                               { return "file" }
func (*lazyHostFile) Freeze()                                    {}
func (*lazyHostFile) Truth() starlark.Bool                       { return starlark.True }
func (*lazyHostFile) Hash() (uint32, error)                      { return 0, fmt.Errorf("unhashable file") }
func (f *lazyHostFile) Attr(name string) (starlark.Value, error) { return starfile.Attr(f, name), nil }
func (*lazyHostFile) AttrNames() []string                        { return starfile.AttrNames() }
