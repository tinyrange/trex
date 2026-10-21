package shell

import (
	"fmt"
	"io"
	"io/fs"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/tinyrange/trex/channel"
	"github.com/tinyrange/trex/filesystem"
	starfile "github.com/tinyrange/trex/storage/star"
)

// OpenFlags describes virtual file access, independently of host OS constants.
type OpenFlags uint8

const (
	Read OpenFlags = 1 << iota
	Write
	Create
	Truncate
	Append
	Exclusive
)

// FileSystem uses absolute slash-separated guest paths only. Open descriptions
// own their offsets; duplicate shell descriptors share the same description.
// Implementations must permit concurrent pipeline stages.
type FileSystem interface {
	Open(string, OpenFlags) (channel.ByteChannel, error)
	Stat(string) (fs.FileInfo, error)
	ReadDir(string) ([]fs.DirEntry, error)
	Mkdir(string) error
	Remove(string) error
}

type inode struct {
	opens    int
	linked   bool
	modified time.Time
	id       uint64
	data     []byte
	mode     fs.FileMode
}

// MemoryFS is a bounded, in-memory Unix filesystem. It never opens host paths.
// Symlinks and ownership are not implemented yet.
type MemoryFS struct {
	mu      sync.Mutex
	nodes   map[string]*inode
	maximum int64
	used    int64
	nextID  uint64
	clock   int64
}

func NewMemoryFS(maximumBytes int64) (*MemoryFS, error) {
	if maximumBytes <= 0 {
		return nil, fmt.Errorf("shell: filesystem budget must be positive")
	}
	return &MemoryFS{nodes: map[string]*inode{"/": {linked: true, id: 1, mode: fs.ModeDir | 0755}}, maximum: maximumBytes, nextID: 1}, nil
}

// ImportDirectory copies trex files into a guest filesystem, preserving no
// host identity. Permission defaults are explicit because Directory carries
// Windows metadata rather than Unix modes.
func ImportDirectory(source *filesystem.Directory, maximumBytes int64) (*MemoryFS, error) {
	m, err := NewMemoryFS(maximumBytes)
	if err != nil {
		return nil, err
	}
	snap := source.Snapshot()
	sort.Slice(snap.Directories, func(i, j int) bool { return len(snap.Directories[i]) < len(snap.Directories[j]) })
	for _, name := range snap.Directories {
		if name != "/" {
			if err := m.Mkdir(name); err != nil {
				return nil, err
			}
		}
	}
	for name, rec := range snap.Files {
		data := rec.Data
		if rec.File != nil {
			if rec.File.Size() > maximumBytes-m.used {
				return nil, fmt.Errorf("shell: filesystem budget exceeded")
			}
			data, err = starfile.ReadAll(rec.File)
			if err != nil {
				return nil, err
			}
		}
		if err := m.WriteFile(name, data, 0644); err != nil {
			return nil, err
		}
	}
	return m, nil
}

func validPath(name string) error {
	if !strings.HasPrefix(name, "/") || path.Clean(name) != name || strings.ContainsRune(name, 0) {
		return fmt.Errorf("shell: invalid guest path %q", name)
	}
	return nil
}
func pathError(op, name string, err error) error { return &fs.PathError{Op: op, Path: name, Err: err} }
func (m *MemoryFS) parent(name string) error {
	p, ok := m.nodes[path.Dir(name)]
	if !ok {
		return fs.ErrNotExist
	}
	if !p.mode.IsDir() {
		return fmt.Errorf("not a directory")
	}
	return nil
}
func (m *MemoryFS) Mkdir(name string) error { return m.MkdirMode(name, 0755) }

func (m *MemoryFS) MkdirMode(name string, mode fs.FileMode) error {
	if err := validPath(name); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.nodes[name]; ok {
		return pathError("mkdir", name, fs.ErrExist)
	}
	if err := m.parent(name); err != nil {
		return pathError("mkdir", name, err)
	}
	m.nextID++
	m.clock++
	m.nodes[name] = &inode{linked: true, id: m.nextID, modified: time.Unix(0, m.clock), mode: fs.ModeDir | mode.Perm()}
	return nil
}
func (m *MemoryFS) Remove(name string) error {
	if err := validPath(name); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	n, ok := m.nodes[name]
	if !ok {
		return pathError("remove", name, fs.ErrNotExist)
	}
	if name == "/" {
		return pathError("remove", name, fs.ErrPermission)
	}
	for p := range m.nodes {
		if path.Dir(p) == name {
			return pathError("remove", name, fmt.Errorf("directory not empty"))
		}
	}
	n.linked = false
	if n.opens == 0 {
		m.used -= int64(len(n.data))
	}
	delete(m.nodes, name)
	return nil
}
func (m *MemoryFS) Open(name string, flags OpenFlags) (channel.ByteChannel, error) {
	return m.OpenMode(name, flags, 0644)
}

// OpenMode applies mode only when creating a new file. Exclusive creation is atomic.
func (m *MemoryFS) OpenMode(name string, flags OpenFlags, mode fs.FileMode) (channel.ByteChannel, error) {
	if err := validPath(name); err != nil {
		return nil, err
	}
	if flags&(Read|Write) == 0 || flags&(Truncate|Append) != 0 && flags&Write == 0 {
		return nil, fmt.Errorf("shell: invalid open flags")
	}
	if name == "/dev/null" || name == "/dev/full" {
		if flags&(Create|Exclusive) == Create|Exclusive {
			return nil, pathError("open", name, fs.ErrExist)
		}
		if name == "/dev/full" {
			return &fullFile{flags: flags}, nil
		}
		return &nullFile{flags: flags}, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	n, ok := m.nodes[name]
	if ok && flags&(Create|Exclusive) == Create|Exclusive {
		return nil, pathError("open", name, fs.ErrExist)
	}
	if !ok {
		if flags&Create == 0 {
			return nil, pathError("open", name, fs.ErrNotExist)
		}
		if err := m.parent(name); err != nil {
			return nil, pathError("open", name, err)
		}
		m.nextID++
		m.clock++
		n = &inode{linked: true, id: m.nextID, modified: time.Unix(0, m.clock), mode: mode.Perm()}
		m.nodes[name] = n
	}
	if n.mode.IsDir() {
		return nil, pathError("open", name, fmt.Errorf("is a directory"))
	}
	if flags&Truncate != 0 {
		m.used -= int64(len(n.data))
		n.data = nil
		m.clock++
		n.modified = time.Unix(0, m.clock)
	}
	n.opens++
	return &memoryFile{fs: m, node: n, flags: flags}, nil
}
func (m *MemoryFS) WriteFile(name string, data []byte, mode fs.FileMode) error {
	f, err := m.Open(name, Write|Create|Truncate)
	if err != nil {
		return err
	}
	defer f.Close()
	if err = channel.WriteAll(f, data); err != nil {
		return err
	}
	m.mu.Lock()
	if opened, ok := f.(*memoryFile); ok {
		opened.node.mode = mode.Perm()
	}
	m.mu.Unlock()
	return nil
}
func (m *MemoryFS) ReadFile(name string) ([]byte, error) {
	f, err := m.Open(name, Read)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}
func (m *MemoryFS) Stat(name string) (fs.FileInfo, error) {
	if err := validPath(name); err != nil {
		return nil, err
	}
	if name == "/dev/null" || name == "/dev/full" {
		return info{name: path.Base(name), mode: fs.ModeDevice | fs.ModeCharDevice | 0666}, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	n, ok := m.nodes[name]
	if !ok {
		return nil, pathError("stat", name, fs.ErrNotExist)
	}
	return info{name: path.Base(name), size: int64(len(n.data)), mode: n.mode, id: n.id, modified: n.modified}, nil
}
func (m *MemoryFS) ReadDir(name string) ([]fs.DirEntry, error) {
	if err := validPath(name); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	n, ok := m.nodes[name]
	if !ok {
		return nil, pathError("readdir", name, fs.ErrNotExist)
	}
	if !n.mode.IsDir() {
		return nil, pathError("readdir", name, fmt.Errorf("not a directory"))
	}
	var result []fs.DirEntry
	for p, n := range m.nodes {
		if p != name && path.Dir(p) == name {
			result = append(result, fs.FileInfoToDirEntry(info{name: path.Base(p), size: int64(len(n.data)), mode: n.mode, id: n.id, modified: n.modified}))
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name() < result[j].Name() })
	return result, nil
}

type info struct {
	modified time.Time
	id       uint64
	name     string
	size     int64
	mode     fs.FileMode
}

func (i info) Inode() uint64      { return i.id }
func (i info) Name() string       { return i.name }
func (i info) Size() int64        { return i.size }
func (i info) Mode() fs.FileMode  { return i.mode }
func (i info) ModTime() time.Time { return i.modified }
func (i info) IsDir() bool        { return i.mode.IsDir() }
func (i info) Sys() any           { return nil }

type memoryFile struct {
	fs     *MemoryFS
	node   *inode
	offset int
	flags  OpenFlags
	closed bool
}

func (f *memoryFile) Read(p []byte) (int, error) {
	f.fs.mu.Lock()
	defer f.fs.mu.Unlock()
	if f.closed {
		return 0, fs.ErrClosed
	}
	if f.flags&Read == 0 {
		return 0, fs.ErrPermission
	}
	if len(p) == 0 {
		return 0, nil
	}
	if f.offset >= len(f.node.data) {
		return 0, io.EOF
	}
	n := copy(p, f.node.data[f.offset:])
	f.offset += n
	return n, nil
}
func (f *memoryFile) Write(p []byte) (int, error) {
	f.fs.mu.Lock()
	defer f.fs.mu.Unlock()
	if f.closed {
		return 0, fs.ErrClosed
	}
	if f.flags&Write == 0 {
		return 0, fs.ErrPermission
	}
	if len(p) == 0 {
		return 0, nil
	}
	if f.flags&Append != 0 {
		f.offset = len(f.node.data)
	}
	growth := int64(f.offset) + int64(len(p)) - int64(len(f.node.data))
	if growth > f.fs.maximum-f.fs.used {
		return 0, fmt.Errorf("shell: filesystem budget exceeded")
	}
	if growth > 0 {
		f.node.data = append(f.node.data, make([]byte, int(growth))...)
		f.fs.used += growth
	}
	f.fs.clock++
	f.node.modified = time.Unix(0, f.fs.clock)
	n := copy(f.node.data[f.offset:], p)
	f.offset += n
	return n, nil
}
func (f *memoryFile) Close() error {
	f.fs.mu.Lock()
	defer f.fs.mu.Unlock()
	if !f.closed {
		f.closed = true
		f.node.opens--
		if !f.node.linked && f.node.opens == 0 {
			f.fs.used -= int64(len(f.node.data))
		}
	}
	return nil
}

type nullFile struct{ flags OpenFlags }

func (f *nullFile) Read(p []byte) (int, error) {
	if f.flags&Read == 0 {
		return 0, fs.ErrPermission
	}
	return 0, io.EOF
}
func (f *nullFile) Write(p []byte) (int, error) {
	if f.flags&Write == 0 {
		return 0, fs.ErrPermission
	}
	return len(p), nil
}
func (*nullFile) Close() error { return nil }
