package tararchive

import (
	"archive/tar"
	"fmt"
	"io"

	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

type Archive struct {
	entries []*Entry
	index   map[string][]int
}

type Entry struct {
	archive    File
	dataOffset int64
	storedSize int64
	header     tar.Header
	path       string
	kind       string
	regular    bool
	hardTarget *Entry
}

type countingReader struct {
	reader io.Reader
	offset int64
}

func (r *countingReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	r.offset += int64(n)
	return n, err
}

func Open(file File, maximumEntries int) (*Archive, error) {
	if maximumEntries <= 0 {
		return nil, fmt.Errorf("tar: maximum_entries must be positive")
	}
	counter := &countingReader{reader: io.NewSectionReader(file, 0, file.Size())}
	reader := tar.NewReader(counter)
	archive := &Archive{index: make(map[string][]int)}
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("tar: read entry %d: %w", len(archive.entries), err)
		}
		if len(archive.entries) >= maximumEntries {
			return nil, fmt.Errorf("tar: entry count exceeds maximum_entries %d", maximumEntries)
		}
		if header.Typeflag == tar.TypeGNUSparse || header.PAXRecords["GNU.sparse.major"] != "" {
			return nil, fmt.Errorf("tar: sparse entry %q is not supported by direct file views", header.Name)
		}
		entry := &Entry{
			archive:    file,
			dataOffset: counter.offset,
			storedSize: header.Size,
			header:     *header,
			path:       storage.CleanPath(header.Name),
			kind:       tarTypeName(header.Typeflag),
			regular:    header.Typeflag == tar.TypeReg || header.Typeflag == tar.TypeRegA,
		}
		archive.index[entry.path] = append(archive.index[entry.path], len(archive.entries))
		archive.entries = append(archive.entries, entry)
		if _, err := io.Copy(io.Discard, reader); err != nil {
			return nil, fmt.Errorf("tar: read entry %q: %w", header.Name, err)
		}
	}
	for _, entry := range archive.entries {
		if entry.header.Typeflag != tar.TypeLink {
			continue
		}
		targetPath := storage.CleanPath(entry.header.Linkname)
		indices := archive.index[targetPath]
		if len(indices) != 0 {
			entry.hardTarget = archive.entries[indices[0]]
		}
	}
	return archive, nil
}

func tarTypeName(typeflag byte) string {
	switch typeflag {
	case tar.TypeReg, tar.TypeRegA:
		return "file"
	case tar.TypeLink:
		return "hardlink"
	case tar.TypeSymlink:
		return "symlink"
	case tar.TypeChar:
		return "character_device"
	case tar.TypeBlock:
		return "block_device"
	case tar.TypeDir:
		return "directory"
	case tar.TypeFifo:
		return "fifo"
	case tar.TypeCont:
		return "contiguous_file"
	case tar.TypeXHeader:
		return "pax_header"
	case tar.TypeXGlobalHeader:
		return "pax_global_header"
	case tar.TypeGNULongName:
		return "gnu_long_name"
	case tar.TypeGNULongLink:
		return "gnu_long_link"
	case tar.TypeGNUSparse:
		return "gnu_sparse"
	}
	return fmt.Sprintf("type_%d", typeflag)
}

func (a *Archive) String() string        { return fmt.Sprintf("<tar entries=%d>", len(a.entries)) }
func (a *Archive) Type() string          { return "tar" }
func (a *Archive) Freeze()               {}
func (a *Archive) Truth() starlark.Bool  { return starlark.True }
func (a *Archive) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: %s", a.Type()) }
func (a *Archive) Get(key starlark.Value) (starlark.Value, bool, error) {
	name, ok := starlark.AsString(key)
	if !ok {
		return nil, false, nil
	}
	entry, ok := a.lookup(name, 0)
	return entry, ok, nil
}
func (a *Archive) Attr(name string) (starlark.Value, error) {
	switch name {
	case "entries":
		values := make([]starlark.Value, len(a.entries))
		for i, entry := range a.entries {
			values[i] = entry
		}
		return starlark.NewList(values), nil
	case "files":
		values := make([]starlark.Value, 0, len(a.entries))
		for _, entry := range a.entries {
			if entry.regular || entry.hardTarget != nil {
				values = append(values, starlark.String(entry.path))
			}
		}
		return starlark.NewList(values), nil
	case "find":
		return starlark.NewBuiltin("find", a.findBuiltin), nil
	}
	return nil, nil
}
func (a *Archive) AttrNames() []string { return []string{"entries", "files", "find"} }

func (a *Archive) findBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	occurrence := 0
	if err := starlark.UnpackArgs("find", args, kwargs, "path", &name, "occurrence?", &occurrence); err != nil {
		return nil, err
	}
	if occurrence < 0 {
		return nil, fmt.Errorf("find: occurrence must be non-negative")
	}
	entry, ok := a.lookup(name, occurrence)
	if !ok {
		return starlark.None, nil
	}
	return entry, nil
}

func (a *Archive) lookup(name string, occurrence int) (*Entry, bool) {
	indices := a.index[storage.CleanPath(name)]
	if occurrence >= len(indices) {
		return nil, false
	}
	return a.entries[indices[occurrence]], true
}

func (f *Entry) dataSource(seen map[*Entry]bool) (*Entry, error) {
	if f.regular {
		return f, nil
	}
	if f.hardTarget == nil {
		return nil, fmt.Errorf("tar: entry %q of type %s has no file data", f.header.Name, f.kind)
	}
	if seen[f] {
		return nil, fmt.Errorf("tar: hard link cycle at %q", f.header.Name)
	}
	seen[f] = true
	return f.hardTarget.dataSource(seen)
}

func (f *Entry) ReadAt(p []byte, off int64) (int, error) {
	source, err := f.dataSource(make(map[*Entry]bool))
	if err != nil {
		return 0, err
	}
	return starfile.ReadSubfileAt(source.archive, source.dataOffset, source.storedSize, p, off)
}
func (f *Entry) WriteAt([]byte, int64) (int, error) {
	return 0, fmt.Errorf("tar entry %q is read-only", f.header.Name)
}
func (f *Entry) Size() int64 {
	if f.regular {
		return f.storedSize
	}
	if f.hardTarget != nil {
		source, err := f.dataSource(make(map[*Entry]bool))
		if err == nil {
			return source.storedSize
		}
	}
	return 0
}
func (f *Entry) String() string {
	return fmt.Sprintf("<tar.%s %q size=%d>", f.kind, f.path, f.Size())
}
func (f *Entry) Type() string          { return "file" }
func (f *Entry) Freeze()               {}
func (f *Entry) Truth() starlark.Bool  { return starlark.True }
func (f *Entry) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: %s", f.Type()) }
func (f *Entry) Attr(name string) (starlark.Value, error) {
	switch name {
	case "name":
		return starlark.String(f.header.Name), nil
	case "path":
		return starlark.String(f.path), nil
	case "entry_type":
		return starlark.String(f.kind), nil
	case "link":
		return starlark.String(f.header.Linkname), nil
	case "mode":
		return starlark.MakeInt64(f.header.Mode), nil
	case "uid":
		return starlark.MakeInt(f.header.Uid), nil
	case "gid":
		return starlark.MakeInt(f.header.Gid), nil
	case "uname":
		return starlark.String(f.header.Uname), nil
	case "gname":
		return starlark.String(f.header.Gname), nil
	case "mtime":
		return starlark.MakeInt64(f.header.ModTime.Unix()), nil
	case "stored_size":
		return starlark.MakeInt64(f.storedSize), nil
	}
	return starfile.Attr(f, name), nil
}
func (f *Entry) AttrNames() []string {
	return []string{"binary", "bytes", "entry_type", "gid", "gname", "hex", "link", "mode", "mtime", "name", "path", "read", "size", "slice", "stored_size", "uid", "uname"}
}
