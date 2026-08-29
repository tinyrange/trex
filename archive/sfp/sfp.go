package sfp

import (
	"encoding/binary"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

const (
	sfpHeaderSize             = uint64(64)
	sfpRecordSize             = uint64(80)
	sfpMagic                  = uint32(0x00504653) // "SFP\x00"
	sfpDirectoryMagic         = uint32(0x00524944) // "DIR\x00"
	sfpDefaultMaximumEntries  = 1_000_000
	sfpDefaultMaximumMetadata = int64(64 << 20)
)

type sfpHeader struct {
	version            uint32
	unknown1           uint64
	firstRecordOffset  uint64
	nameTableOffset    uint64
	dataOffset         uint64
	archiveSize        uint64
	packageLabelOffset uint64
	unknown3           uint64
}

type sfpRecord struct {
	offset       uint64
	nameOffset   uint64
	unknown1     uint32
	parentOffset uint64
	isDirectory  bool
	fileLength   uint64
	modifiedTime uint64
	createdTime  uint64
	unknown2     uint64
	flags        uint64
	startOffset  uint64
	dataLength   uint32
}

type Archive struct {
	file         starfile.File
	header       sfpHeader
	packageLabel string
	entries      []*Entry
	index        map[string]int
}

type Entry struct {
	archive *Archive
	record  sfpRecord
	name    string
	path    string
	parent  string
}

func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	maximumEntries := sfpDefaultMaximumEntries
	maximumMetadata := sfpDefaultMaximumMetadata
	if err := starlark.UnpackArgs("sfp", args, kwargs, "file", &value, "maximum_entries?", &maximumEntries, "maximum_metadata?", &maximumMetadata); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("sfp: got %s, want file", value.Type())
	}
	return Open(file, maximumEntries, maximumMetadata)
}

func Open(file starfile.File, maximumEntries int, maximumMetadata int64) (*Archive, error) {
	if maximumEntries <= 0 {
		return nil, fmt.Errorf("sfp: maximum_entries must be positive")
	}
	if maximumMetadata < int64(sfpHeaderSize) {
		return nil, fmt.Errorf("sfp: maximum_metadata must be at least %d", sfpHeaderSize)
	}
	if file.Size() < int64(sfpHeaderSize) {
		return nil, fmt.Errorf("sfp: file is shorter than the %d-byte header", sfpHeaderSize)
	}

	headerBytes := make([]byte, sfpHeaderSize)
	n, err := file.ReadAt(headerBytes, 0)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("sfp: read header: %w", err)
	}
	if n != len(headerBytes) {
		return nil, fmt.Errorf("sfp: truncated header: read %d of %d bytes", n, len(headerBytes))
	}
	if binary.LittleEndian.Uint32(headerBytes[0:4]) != sfpMagic {
		return nil, fmt.Errorf("sfp: invalid signature")
	}
	header := sfpHeader{
		version:            binary.LittleEndian.Uint32(headerBytes[4:8]),
		unknown1:           binary.LittleEndian.Uint64(headerBytes[8:16]),
		firstRecordOffset:  binary.LittleEndian.Uint64(headerBytes[16:24]),
		nameTableOffset:    binary.LittleEndian.Uint64(headerBytes[24:32]),
		dataOffset:         binary.LittleEndian.Uint64(headerBytes[32:40]),
		archiveSize:        binary.LittleEndian.Uint64(headerBytes[40:48]),
		packageLabelOffset: binary.LittleEndian.Uint64(headerBytes[48:56]),
		unknown3:           binary.LittleEndian.Uint64(headerBytes[56:64]),
	}
	if header.version != 1 {
		return nil, fmt.Errorf("sfp: unsupported version %d", header.version)
	}
	fileSize := uint64(file.Size())
	if header.archiveSize > fileSize {
		return nil, fmt.Errorf("sfp: declared archive size %d exceeds file size %d", header.archiveSize, fileSize)
	}
	if header.archiveSize < sfpHeaderSize || header.dataOffset < sfpHeaderSize || header.dataOffset > header.archiveSize {
		return nil, fmt.Errorf("sfp: invalid data offset %d", header.dataOffset)
	}
	if header.nameTableOffset < sfpHeaderSize || header.nameTableOffset > header.dataOffset {
		return nil, fmt.Errorf("sfp: invalid name table offset %d", header.nameTableOffset)
	}
	if header.firstRecordOffset < sfpHeaderSize || header.firstRecordOffset > header.nameTableOffset || sfpRecordSize > header.nameTableOffset-header.firstRecordOffset {
		return nil, fmt.Errorf("sfp: invalid first directory record offset %d", header.firstRecordOffset)
	}
	if header.dataOffset > uint64(maximumMetadata) {
		return nil, fmt.Errorf("sfp: metadata size %d exceeds maximum_metadata %d", header.dataOffset, maximumMetadata)
	}

	metadata := make([]byte, int(header.dataOffset))
	copy(metadata, headerBytes)
	if len(metadata) > len(headerBytes) {
		n, err := file.ReadAt(metadata[len(headerBytes):], int64(len(headerBytes)))
		if err != nil && err != io.EOF {
			return nil, fmt.Errorf("sfp: read metadata: %w", err)
		}
		if n != len(metadata)-len(headerBytes) {
			return nil, fmt.Errorf("sfp: truncated metadata: read %d of %d bytes", n, len(metadata)-len(headerBytes))
		}
	}
	archive := &Archive{file: file, header: header, index: make(map[string]int)}
	nameAt := func(offset uint64) (string, error) {
		if offset == 0 {
			return "", nil
		}
		if offset < header.nameTableOffset || offset >= header.dataOffset {
			return "", fmt.Errorf("name offset %d is outside the name table", offset)
		}
		bytes := metadata[offset:header.dataOffset]
		end := strings.IndexByte(string(bytes), 0)
		if end < 0 {
			return "", fmt.Errorf("name at offset %d is not NUL-terminated", offset)
		}
		return string(bytes[:end]), nil
	}
	if header.packageLabelOffset != 0 {
		label, err := nameAt(header.packageLabelOffset)
		if err != nil {
			return nil, fmt.Errorf("sfp: package label: %w", err)
		}
		archive.packageLabel = label
	}

	seen := make(map[uint64]bool)
	var visit func(uint64, uint64, string) error
	visit = func(offset, expectedParent uint64, parentPath string) error {
		if len(archive.entries) >= maximumEntries {
			return fmt.Errorf("sfp: entry count exceeds maximum_entries %d", maximumEntries)
		}
		if seen[offset] {
			return fmt.Errorf("sfp: directory record cycle or duplicate at offset %d", offset)
		}
		seen[offset] = true
		if offset < header.firstRecordOffset || offset > header.nameTableOffset || sfpRecordSize > header.nameTableOffset-offset {
			return fmt.Errorf("sfp: directory record at offset %d is outside the record table", offset)
		}
		data := metadata[offset : offset+sfpRecordSize]
		if binary.LittleEndian.Uint32(data[0:4]) != sfpDirectoryMagic {
			return fmt.Errorf("sfp: invalid directory record signature at offset %d", offset)
		}
		record := sfpRecord{
			offset:       offset,
			nameOffset:   binary.LittleEndian.Uint64(data[4:12]),
			unknown1:     binary.LittleEndian.Uint32(data[12:16]),
			parentOffset: binary.LittleEndian.Uint64(data[16:24]),
			isDirectory:  binary.LittleEndian.Uint32(data[24:28]) != 0,
			fileLength:   binary.LittleEndian.Uint64(data[28:36]),
			modifiedTime: binary.LittleEndian.Uint64(data[36:44]),
			createdTime:  binary.LittleEndian.Uint64(data[44:52]),
			unknown2:     binary.LittleEndian.Uint64(data[52:60]),
			flags:        binary.LittleEndian.Uint64(data[60:68]),
			startOffset:  binary.LittleEndian.Uint64(data[68:76]),
			dataLength:   binary.LittleEndian.Uint32(data[76:80]),
		}
		if offset != header.firstRecordOffset && record.parentOffset != expectedParent {
			return fmt.Errorf("sfp: record at offset %d names parent %d, want %d", offset, record.parentOffset, expectedParent)
		}
		name, err := nameAt(record.nameOffset)
		if err != nil {
			return fmt.Errorf("sfp: record at offset %d: %w", offset, err)
		}
		if offset != header.firstRecordOffset {
			if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\\") {
				return fmt.Errorf("sfp: invalid entry name %q at offset %d", name, offset)
			}
		}
		entryPath := parentPath
		if name != "" {
			entryPath = path.Join(parentPath, name)
		}
		entryPath = storage.CleanPath(entryPath)
		if _, exists := archive.index[entryPath]; exists {
			return fmt.Errorf("sfp: duplicate path %q", entryPath)
		}
		entry := &Entry{archive: archive, record: record, name: name, path: entryPath, parent: storage.CleanPath(parentPath)}
		archive.index[entryPath] = len(archive.entries)
		archive.entries = append(archive.entries, entry)

		length := uint64(record.dataLength)
		if record.isDirectory {
			if length%sfpRecordSize != 0 {
				return fmt.Errorf("sfp: directory %q has misaligned child record length %d", entryPath, length)
			}
			if length != 0 && (record.startOffset < header.firstRecordOffset || record.startOffset > header.nameTableOffset || length > header.nameTableOffset-record.startOffset) {
				return fmt.Errorf("sfp: directory %q has child records outside the record table", entryPath)
			}
			for childOffset := record.startOffset; childOffset < record.startOffset+length; childOffset += sfpRecordSize {
				if err := visit(childOffset, offset, entryPath); err != nil {
					return err
				}
			}
			return nil
		}
		if record.startOffset > header.archiveSize || length > header.archiveSize-record.startOffset {
			return fmt.Errorf("sfp: file %q payload extends past the archive", entryPath)
		}
		if length != 0 && record.startOffset < header.dataOffset {
			return fmt.Errorf("sfp: file %q payload overlaps metadata", entryPath)
		}
		return nil
	}
	if err := visit(header.firstRecordOffset, 0, "/"); err != nil {
		return nil, err
	}
	return archive, nil
}

func (a *Archive) String() string {
	return fmt.Sprintf("<sfp package=%q entries=%d>", a.packageLabel, len(a.entries))
}
func (a *Archive) Type() string          { return "sfp" }
func (a *Archive) Freeze()               {}
func (a *Archive) Truth() starlark.Bool  { return starlark.True }
func (a *Archive) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: %s", a.Type()) }
func (a *Archive) Get(key starlark.Value) (starlark.Value, bool, error) {
	name, ok := starlark.AsString(key)
	if !ok {
		return nil, false, nil
	}
	entry, ok := a.lookup(name)
	return entry, ok, nil
}
func (a *Archive) lookup(name string) (*Entry, bool) {
	index, ok := a.index[storage.CleanPath(name)]
	if !ok {
		return nil, false
	}
	return a.entries[index], true
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
			if !entry.record.isDirectory {
				values = append(values, starlark.String(entry.path))
			}
		}
		return starlark.NewList(values), nil
	case "find":
		return starlark.NewBuiltin("find", a.findBuiltin), nil
	case "package_label":
		return starlark.String(a.packageLabel), nil
	case "version":
		return starlark.MakeUint64(uint64(a.header.version)), nil
	case "archive_size":
		return starlark.MakeUint64(a.header.archiveSize), nil
	case "data_offset":
		return starlark.MakeUint64(a.header.dataOffset), nil
	}
	return nil, nil
}
func (a *Archive) AttrNames() []string {
	return []string{"archive_size", "data_offset", "entries", "files", "find", "package_label", "version"}
}
func (a *Archive) findBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	if err := starlark.UnpackArgs("find", args, kwargs, "path", &name); err != nil {
		return nil, err
	}
	entry, ok := a.lookup(name)
	if !ok {
		return starlark.None, nil
	}
	return entry, nil
}

func (f *Entry) ReadAt(p []byte, off int64) (int, error) {
	if f.record.isDirectory {
		return 0, fmt.Errorf("sfp: entry %q is a directory", f.path)
	}
	return starfile.ReadSubfileAt(f.archive.file, int64(f.record.startOffset), int64(f.record.dataLength), p, off)
}
func (f *Entry) WriteAt([]byte, int64) (int, error) {
	return 0, fmt.Errorf("sfp entry %q is read-only", f.path)
}
func (f *Entry) Size() int64 {
	if f.record.isDirectory {
		return 0
	}
	return int64(f.record.dataLength)
}
func (f *Entry) String() string {
	kind := "file"
	if f.record.isDirectory {
		kind = "directory"
	}
	return fmt.Sprintf("<sfp.%s %q size=%d>", kind, f.path, f.Size())
}
func (f *Entry) Type() string          { return "file" }
func (f *Entry) Freeze()               {}
func (f *Entry) Truth() starlark.Bool  { return starlark.True }
func (f *Entry) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: %s", f.Type()) }
func (f *Entry) Attr(name string) (starlark.Value, error) {
	switch name {
	case "name":
		return starlark.String(f.name), nil
	case "path":
		return starlark.String(f.path), nil
	case "parent":
		return starlark.String(f.parent), nil
	case "entry_type":
		if f.record.isDirectory {
			return starlark.String("directory"), nil
		}
		return starlark.String("file"), nil
	case "created_time":
		return starlark.MakeUint64(f.record.createdTime), nil
	case "modified_time":
		return starlark.MakeUint64(f.record.modifiedTime), nil
	case "file_length":
		return starlark.MakeUint64(f.record.fileLength), nil
	case "stored_size":
		return starlark.MakeUint64(uint64(f.record.dataLength)), nil
	case "record_offset":
		return starlark.MakeUint64(f.record.offset), nil
	case "payload_offset":
		return starlark.MakeUint64(f.record.startOffset), nil
	case "flags":
		return starlark.MakeUint64(f.record.flags), nil
	}
	return starfile.Attr(f, name), nil
}
func (f *Entry) AttrNames() []string {
	return []string{"binary", "bytes", "created_time", "entry_type", "file_length", "flags", "hex", "modified_time", "name", "parent", "path", "payload_offset", "read", "record_offset", "size", "slice", "stored_size"}
}
