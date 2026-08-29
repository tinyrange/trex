package ar

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

type File = starfile.File

var fileAttr = starfile.Attr

const (
	arHeaderSize             = int64(60)
	arDefaultMaximumEntries  = 1_000_000
	arDefaultMaximumMetadata = int64(64 << 20)
)

// Builtin implements the archive.ar Starlark constructor.
func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	maximumEntries := arDefaultMaximumEntries
	maximumMetadata := arDefaultMaximumMetadata
	if err := starlark.UnpackArgs("ar", args, kwargs, "file", &value, "maximum_entries?", &maximumEntries, "maximum_metadata?", &maximumMetadata); err != nil {
		return nil, err
	}
	file, ok := value.(File)
	if !ok {
		return nil, fmt.Errorf("ar: got %s, want file", value.Type())
	}
	return openWithLimits(file, maximumEntries, maximumMetadata)
}

type arArchive struct {
	entries []*arEntryFile
	index   map[string][]int
}

type arRawEntry struct {
	name       string
	nameOffset int64
	dataOffset int64
	size       int64
	mtime      int64
	uid        int64
	gid        int64
	mode       uint64
}

func Open(file File) (*arArchive, error) {
	return openWithLimits(file, arDefaultMaximumEntries, arDefaultMaximumMetadata)
}

func openWithLimits(file File, maximumEntries int, maximumMetadata int64) (*arArchive, error) {
	if maximumEntries <= 0 {
		return nil, fmt.Errorf("ar: maximum_entries must be positive")
	}
	if maximumMetadata <= 0 {
		return nil, fmt.Errorf("ar: maximum_metadata must be positive")
	}
	magic := make([]byte, 8)
	if _, err := file.ReadAt(magic, 0); err != nil {
		return nil, fmt.Errorf("ar: read signature: %w", err)
	}
	if string(magic) != "!<arch>\n" {
		return nil, fmt.Errorf("ar: invalid global signature")
	}

	var raw []arRawEntry
	var stringTable []byte
	var metadataSize int64
	for offset := int64(len(magic)); offset < file.Size(); {
		if file.Size()-offset < arHeaderSize {
			return nil, fmt.Errorf("ar: truncated member header at offset %d", offset)
		}
		header := make([]byte, arHeaderSize)
		if _, err := file.ReadAt(header, offset); err != nil {
			return nil, fmt.Errorf("ar: read member header at offset %d: %w", offset, err)
		}
		if string(header[58:60]) != "`\n" {
			return nil, fmt.Errorf("ar: invalid member header at offset %d", offset)
		}

		memberSize, err := parseARNumber(header[48:58], 10, "size")
		if err != nil {
			return nil, fmt.Errorf("ar: member at offset %d: %w", offset, err)
		}
		if memberSize < 0 {
			return nil, fmt.Errorf("ar: member at offset %d has negative size", offset)
		}
		dataOffset := offset + arHeaderSize
		if dataOffset > file.Size() || memberSize > file.Size()-dataOffset {
			return nil, fmt.Errorf("ar: member at offset %d extends past end of file", offset)
		}

		mtime, err := parseARNumber(header[16:28], 10, "timestamp")
		if err != nil {
			return nil, fmt.Errorf("ar: member at offset %d: %w", offset, err)
		}
		uid, err := parseARNumber(header[28:34], 10, "uid")
		if err != nil {
			return nil, fmt.Errorf("ar: member at offset %d: %w", offset, err)
		}
		gid, err := parseARNumber(header[34:40], 10, "gid")
		if err != nil {
			return nil, fmt.Errorf("ar: member at offset %d: %w", offset, err)
		}
		mode, err := parseARUnsigned(header[40:48], 8, "mode")
		if err != nil {
			return nil, fmt.Errorf("ar: member at offset %d: %w", offset, err)
		}

		name := strings.TrimSpace(string(header[:16]))
		entry := arRawEntry{name: name, nameOffset: -1, dataOffset: dataOffset, size: memberSize, mtime: mtime, uid: uid, gid: gid, mode: mode}
		switch {
		case name == "//":
			if memberSize > maximumMetadata-metadataSize {
				return nil, fmt.Errorf("ar: filename metadata exceeds maximum_metadata %d", maximumMetadata)
			}
			metadataSize += memberSize
			stringTable = make([]byte, int(memberSize))
			if _, err := file.ReadAt(stringTable, dataOffset); err != nil && err != io.EOF {
				return nil, fmt.Errorf("ar: read GNU filename table: %w", err)
			}
		case name == "/" || strings.HasPrefix(name, "/SYM64/"):
			// GNU symbol tables describe object archives, not package payloads.
		case strings.HasPrefix(name, "#1/"):
			nameSize, err := strconv.ParseInt(strings.TrimSpace(strings.TrimPrefix(name, "#1/")), 10, 64)
			if err != nil || nameSize < 0 || nameSize > memberSize {
				return nil, fmt.Errorf("ar: invalid BSD extended filename length %q", name)
			}
			if nameSize > maximumMetadata-metadataSize {
				return nil, fmt.Errorf("ar: filename metadata exceeds maximum_metadata %d", maximumMetadata)
			}
			metadataSize += nameSize
			nameData := make([]byte, int(nameSize))
			if _, err := file.ReadAt(nameData, dataOffset); err != nil && err != io.EOF {
				return nil, fmt.Errorf("ar: read BSD extended filename: %w", err)
			}
			entry.name = strings.TrimRight(string(nameData), "\x00")
			entry.dataOffset += nameSize
			entry.size -= nameSize
			if len(raw) >= maximumEntries {
				return nil, fmt.Errorf("ar: entry count exceeds maximum_entries %d", maximumEntries)
			}
			raw = append(raw, entry)
		case strings.HasPrefix(name, "/"):
			nameOffset, err := strconv.ParseInt(strings.TrimPrefix(name, "/"), 10, 64)
			if err != nil || nameOffset < 0 {
				return nil, fmt.Errorf("ar: invalid GNU filename reference %q", name)
			}
			entry.nameOffset = nameOffset
			if len(raw) >= maximumEntries {
				return nil, fmt.Errorf("ar: entry count exceeds maximum_entries %d", maximumEntries)
			}
			raw = append(raw, entry)
		default:
			entry.name = strings.TrimSuffix(name, "/")
			if len(raw) >= maximumEntries {
				return nil, fmt.Errorf("ar: entry count exceeds maximum_entries %d", maximumEntries)
			}
			raw = append(raw, entry)
		}

		next := dataOffset + memberSize
		if next&1 != 0 {
			next++
		}
		if next < dataOffset || next > file.Size() {
			return nil, fmt.Errorf("ar: invalid member boundary at offset %d", offset)
		}
		offset = next
	}

	archive := &arArchive{index: make(map[string][]int)}
	for _, entry := range raw {
		if entry.nameOffset >= 0 {
			name, err := arGNUFilename(stringTable, entry.nameOffset)
			if err != nil {
				return nil, err
			}
			entry.name = name
		}
		if entry.name == "" {
			return nil, fmt.Errorf("ar: empty member name")
		}
		value := &arEntryFile{archive: file, entry: entry}
		archive.index[entry.name] = append(archive.index[entry.name], len(archive.entries))
		archive.entries = append(archive.entries, value)
	}
	return archive, nil
}

func parseARNumber(field []byte, base int, name string) (int64, error) {
	text := strings.TrimSpace(string(field))
	if text == "" {
		return 0, nil
	}
	value, err := strconv.ParseInt(text, base, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid %s %q", name, text)
	}
	return value, nil
}

func parseARUnsigned(field []byte, base int, name string) (uint64, error) {
	text := strings.TrimSpace(string(field))
	if text == "" {
		return 0, nil
	}
	value, err := strconv.ParseUint(text, base, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid %s %q", name, text)
	}
	return value, nil
}

func arGNUFilename(table []byte, offset int64) (string, error) {
	if offset < 0 || offset >= int64(len(table)) {
		return "", fmt.Errorf("ar: GNU filename offset %d is outside the filename table", offset)
	}
	rest := table[offset:]
	end := strings.IndexByte(string(rest), '\n')
	if end < 0 {
		return "", fmt.Errorf("ar: unterminated GNU filename at table offset %d", offset)
	}
	return strings.TrimSuffix(strings.TrimRight(string(rest[:end]), "\x00"), "/"), nil
}

func (a *arArchive) String() string        { return fmt.Sprintf("<ar entries=%d>", len(a.entries)) }
func (a *arArchive) Type() string          { return "ar" }
func (a *arArchive) Freeze()               {}
func (a *arArchive) Truth() starlark.Bool  { return starlark.True }
func (a *arArchive) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: %s", a.Type()) }
func (a *arArchive) Get(key starlark.Value) (starlark.Value, bool, error) {
	name, ok := starlark.AsString(key)
	if !ok {
		return nil, false, nil
	}
	entry, ok := a.lookup(name, 0)
	return entry, ok, nil
}
func (a *arArchive) Attr(name string) (starlark.Value, error) {
	switch name {
	case "entries":
		values := make([]starlark.Value, len(a.entries))
		for i, entry := range a.entries {
			values[i] = entry
		}
		return starlark.NewList(values), nil
	case "files":
		values := make([]starlark.Value, len(a.entries))
		for i, entry := range a.entries {
			values[i] = starlark.String(entry.entry.name)
		}
		return starlark.NewList(values), nil
	case "find":
		return starlark.NewBuiltin("find", a.findBuiltin), nil
	}
	return nil, nil
}
func (a *arArchive) AttrNames() []string { return []string{"entries", "files", "find"} }

func (a *arArchive) findBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	occurrence := 0
	if err := starlark.UnpackArgs("find", args, kwargs, "name", &name, "occurrence?", &occurrence); err != nil {
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

func (a *arArchive) lookup(name string, occurrence int) (*arEntryFile, bool) {
	name = strings.TrimSuffix(name, "/")
	indices := a.index[name]
	if occurrence >= len(indices) {
		return nil, false
	}
	return a.entries[indices[occurrence]], true
}

type arEntryFile struct {
	archive File
	entry   arRawEntry
}

func (f *arEntryFile) ReadAt(p []byte, off int64) (int, error) {
	return readSubfileAt(f.archive, f.entry.dataOffset, f.entry.size, p, off)
}
func (f *arEntryFile) WriteAt([]byte, int64) (int, error) {
	return 0, fmt.Errorf("ar entry %q is read-only", f.entry.name)
}
func (f *arEntryFile) Size() int64 { return f.entry.size }
func (f *arEntryFile) String() string {
	return fmt.Sprintf("<ar.file %q size=%d>", f.entry.name, f.entry.size)
}
func (f *arEntryFile) Type() string          { return "file" }
func (f *arEntryFile) Freeze()               {}
func (f *arEntryFile) Truth() starlark.Bool  { return starlark.True }
func (f *arEntryFile) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: %s", f.Type()) }
func (f *arEntryFile) Attr(name string) (starlark.Value, error) {
	switch name {
	case "name":
		return starlark.String(f.entry.name), nil
	case "mtime":
		return starlark.MakeInt64(f.entry.mtime), nil
	case "uid":
		return starlark.MakeInt64(f.entry.uid), nil
	case "gid":
		return starlark.MakeInt64(f.entry.gid), nil
	case "mode":
		return starlark.MakeUint64(f.entry.mode), nil
	}
	return fileAttr(f, name), nil
}
func (f *arEntryFile) AttrNames() []string {
	return []string{"binary", "bytes", "gid", "hex", "mode", "mtime", "name", "read", "size", "slice", "uid"}
}

func readSubfileAt(base File, baseOffset, size int64, p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("negative offset")
	}
	if off >= size {
		return 0, io.EOF
	}
	requested := len(p)
	if remaining := size - off; int64(len(p)) > remaining {
		p = p[:remaining]
	}
	n, err := base.ReadAt(p, baseOffset+off)
	if err != nil && err != io.EOF {
		return n, err
	}
	if n < requested {
		return n, io.EOF
	}
	return n, nil
}
