package ufs

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"path"
	"sort"
	"time"

	"github.com/tinyrange/trex/filesystem/unixfs"
	"github.com/tinyrange/trex/storage"
	ccfs "j5.nz/cc/fsimage"
)

type BuildOptions struct {
	Size, Extra int64
	// Layout is "raw" or "openbsd". Size excludes the OpenBSD disk prefix.
	Layout    string
	Timestamp uint32
}

// Build creates an in-memory FFS1 filesystem with Unix metadata and hardlinks.
// Payload readers are borrowed, not copied or extracted to the host.
func Build(ctx context.Context, input []unixfs.Entry, options BuildOptions) (storage.Reader, error) {
	if options.Size < 0 || options.Extra < 0 || options.Size > 32<<30 || options.Extra > 32<<30 {
		return nil, fmt.Errorf("ffs: capacity must be between zero and 32 GiB")
	}
	if options.Layout != "raw" && options.Layout != "openbsd" {
		return nil, fmt.Errorf("ffs: layout must be raw or openbsd")
	}
	entries, err := unixfs.Normalize(input)
	if err != nil {
		return nil, err
	}
	nodes := map[string]*buildNode{}
	var payload int64
	for _, entry := range entries {
		if entry.Data != nil {
			if entry.Data.Size() > (32<<30)-payload {
				return nil, fmt.Errorf("ffs: payload exceeds 32 GiB")
			}
			payload += entry.Data.Size()
		}
		if entry.Major > 255 || entry.Minor > 0xffffff {
			return nil, fmt.Errorf("ffs: device number out of range")
		}
		nodes[entry.Path] = &buildNode{entry: entry, key: entry.Path, children: map[string]*buildNode{}}
	}
	for _, entry := range entries {
		node := nodes[entry.Path]
		if entry.Hardlink {
			node = nodes[entry.Target]
		}
		if entry.Path != "." {
			nodes[path.Dir(entry.Path)].children[path.Base(entry.Path)] = node
		}
	}
	if options.Size == 0 && payload > (32<<30)-options.Extra {
		return nil, fmt.Errorf("ffs: estimated payload and extra exceed 32 GiB")
	}
	return ccfs.BuildFFS(ctx, buildDir{nodes["."]}, ccfs.FFSOptions{
		SizeBytes: options.Size, ExtraBytes: options.Extra, Raw: options.Layout == "raw",
		Timestamp: time.Unix(int64(options.Timestamp), 0),
	})
}

type buildNode struct {
	entry    unixfs.Entry
	key      string
	children map[string]*buildNode
}

func (n *buildNode) mode() fs.FileMode {
	e := n.entry
	m := fs.FileMode(e.Mode & 0777)
	if e.Mode&04000 != 0 {
		m |= fs.ModeSetuid
	}
	if e.Mode&02000 != 0 {
		m |= fs.ModeSetgid
	}
	if e.Mode&01000 != 0 {
		m |= fs.ModeSticky
	}
	switch e.Mode & 0170000 {
	case unixfs.Directory:
		m |= fs.ModeDir
	case unixfs.Symlink:
		m |= fs.ModeSymlink
	case unixfs.Character:
		m |= fs.ModeDevice | fs.ModeCharDevice
	case unixfs.Block:
		m |= fs.ModeDevice
	case unixfs.FIFO:
		m |= fs.ModeNamedPipe
	case unixfs.Socket:
		m |= fs.ModeSocket
	}
	return m
}
func (n *buildNode) ModTime() time.Time      { return time.Unix(int64(n.entry.Mtime), 0) }
func (n *buildNode) Owner() (uint32, uint32) { return n.entry.UID, n.entry.GID }
func (n *buildNode) RDev() uint32 {
	// BSD 32-bit dev_t: 8 major bits, 24 minor bits around the major byte.
	return (n.entry.Minor & 255) | (n.entry.Major << 8) | ((n.entry.Minor & 0xffff00) << 8)
}

type buildDir struct{ *buildNode }

func (n buildDir) Stat() fs.FileMode { return n.mode() }
func (n buildDir) ReadDir() ([]ccfs.DirEnt, error) {
	result := make([]ccfs.DirEnt, 0, len(n.children))
	for name, child := range n.children {
		result = append(result, ccfs.DirEnt{Name: name, Mode: child.mode()})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result, nil
}
func (n buildDir) Lookup(name string) (ccfs.Entry, error) {
	child := n.children[name]
	if child == nil {
		return ccfs.Entry{}, fs.ErrNotExist
	}
	switch child.entry.Mode & 0170000 {
	case unixfs.Directory:
		return ccfs.Entry{Dir: buildDir{child}}, nil
	case unixfs.Symlink:
		return ccfs.Entry{Symlink: buildLink{child}}, nil
	default:
		return ccfs.Entry{File: buildFile{child}}, nil
	}
}

type buildLink struct{ *buildNode }

func (n buildLink) Stat() fs.FileMode { return n.mode() }
func (n buildLink) Target() string    { return n.entry.Target }

type buildFile struct{ *buildNode }

func (n buildFile) Stat() (uint64, fs.FileMode) {
	var size uint64
	if n.entry.Data != nil {
		size = uint64(n.entry.Data.Size())
	}
	return size, n.mode()
}
func (n buildFile) HardlinkKey() string { return n.key }
func (n buildFile) ReadAt(off uint64, size uint32) ([]byte, error) {
	if n.entry.Data == nil {
		return nil, io.EOF
	}
	length := n.entry.Data.Size()
	if off > uint64(length) || uint64(size) > uint64(length)-off {
		return nil, io.EOF
	}
	data := make([]byte, size)
	count, err := n.entry.Data.ReadAt(data, int64(off))
	if count != len(data) && err == nil {
		err = io.ErrUnexpectedEOF
	}
	return data[:count], err
}
