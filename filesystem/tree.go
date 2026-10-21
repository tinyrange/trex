package filesystem

import (
	"fmt"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"io/fs"
	"path"
	"sort"
	"strings"
)

// Tree is an immutable project view with demand-driven lookup and file access.
// Paths are slash-separated, root-relative (the root is "" or "."). Symlinks
// and gitlinks are entries, not implicitly followed or cloned repositories.
// Readers borrow the owning tree/repository's lifetime.
type Tree interface {
	Lookup(string) (TreeInfo, error)
	ReadDir(string) ([]TreeEntry, error)
	OpenFile(string) (storage.Reader, error)
}
type TreeEntry struct{ Name, Kind string }
type TreeInfo struct {
	Kind string
	Mode uint32
	Size int64
}

// TreeSource captures a stable view, not a physically read-only backend or a
// durable publication. It need not enumerate the tree or read file payloads.
type TreeSource interface{ SnapshotTree() (Tree, error) }

// ProjectPath checks a portable root-relative project path without silently
// turning traversal or an absolute path into access to another entry.
func ProjectPath(name string) (string, error) {
	if strings.HasPrefix(name, "/") || strings.ContainsAny(name, "\\\x00") {
		return "", fmt.Errorf("invalid project path %q", name)
	}
	for _, part := range strings.Split(name, "/") {
		if part == ".." {
			return "", fmt.Errorf("parent traversal denied")
		}
	}
	return path.Clean(name), nil
}
func (d *Directory) SnapshotTree() (Tree, error) { return &directoryTree{snapshot: d.Snapshot()}, nil }

type directoryTree struct{ snapshot Snapshot }

func (d *directoryTree) Lookup(name string) (TreeInfo, error) {
	p, e := ProjectPath(name)
	if e != nil {
		return TreeInfo{}, e
	}
	p = storage.CleanPath(p)
	if file, ok := d.snapshot.Files[p]; ok {
		return TreeInfo{Kind: "file", Mode: 0644, Size: file.Size}, nil
	}
	i := sort.SearchStrings(d.snapshot.Directories, p)
	if i < len(d.snapshot.Directories) && d.snapshot.Directories[i] == p {
		return TreeInfo{Kind: "dir", Mode: 0755}, nil
	}
	return TreeInfo{}, fmt.Errorf("%w: %s", fs.ErrNotExist, name)
}
func (d *directoryTree) ReadDir(name string) ([]TreeEntry, error) {
	p, e := ProjectPath(name)
	if e != nil {
		return nil, e
	}
	p = storage.CleanPath(p)
	info, e := d.Lookup(strings.TrimPrefix(p, "/"))
	if e != nil {
		return nil, e
	}
	if info.Kind != "dir" {
		return nil, fmt.Errorf("not a directory: %s", name)
	}
	entries := []TreeEntry{}
	for _, dir := range d.snapshot.Directories {
		if dir != p && path.Dir(dir) == p {
			entries = append(entries, TreeEntry{Name: path.Base(dir), Kind: "dir"})
		}
	}
	for file := range d.snapshot.Files {
		if path.Dir(file) == p {
			entries = append(entries, TreeEntry{Name: path.Base(file), Kind: "file"})
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	return entries, nil
}
func (d *directoryTree) OpenFile(name string) (storage.Reader, error) {
	p, e := ProjectPath(name)
	if e != nil {
		return nil, e
	}
	p = storage.CleanPath(p)
	file, ok := d.snapshot.Files[p]
	if !ok {
		return nil, fmt.Errorf("%w: %s", fs.ErrNotExist, name)
	}
	if file.File != nil {
		return file.File, nil
	}
	return &starfile.Bytes{Name: p, Data: file.Data}, nil
}
