package installshield

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
	"io"
	"path"
	"strings"
)

// sfxArchive is InstallShield's uncompressed setup launcher container. The
// launcher stores a 46-byte header followed by 312-byte file records and their
// exact payload extents. A cabinet inside a bundled prerequisite is not the
// outer container; recognize this envelope before scanning embedded cabinets.
type sfxArchive struct {
	files map[string]starfile.File
	names []string
	size  int64
}

func peOverlayOffset(file starfile.File) (int64, bool) {
	image, err := pe.NewFile(file)
	if err != nil {
		return 0, false
	}
	defer image.Close()
	var end uint64
	switch header := image.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		end = uint64(header.SizeOfHeaders)
	case *pe.OptionalHeader64:
		end = uint64(header.SizeOfHeaders)
	default:
		return 0, false
	}
	for _, section := range image.Sections {
		if section.Size == 0 {
			continue
		}
		limit := uint64(section.Offset) + uint64(section.Size)
		if limit > uint64(file.Size()) {
			return 0, false
		}
		if limit > end {
			end = limit
		}
	}
	return int64(end), end < uint64(file.Size())
}

func openSFX(file starfile.File, offset int64) (*sfxArchive, bool, error) {
	if offset < 0 || offset > file.Size() || file.Size()-offset < 46 {
		return nil, false, nil
	}
	header := make([]byte, 46)
	if _, err := io.ReadFull(io.NewSectionReader(file, offset, 46), header); err != nil {
		return nil, false, err
	}
	if !bytes.Equal(header[:14], []byte("InstallShield\x00")) {
		return nil, false, nil
	}
	count := binary.LittleEndian.Uint32(header[14:18])
	if count == 0 || count > 65536 {
		return nil, true, fmt.Errorf("installshield SFX: invalid file count %d", count)
	}
	for _, b := range header[18:] {
		if b != 0 {
			return nil, true, fmt.Errorf("installshield SFX: unsupported header flags")
		}
	}
	archive := &sfxArchive{files: map[string]starfile.File{}}
	pos := offset + 46
	for i := uint32(0); i < count; i++ {
		if file.Size()-pos < 312 {
			return nil, true, fmt.Errorf("installshield SFX: truncated file record %d", i)
		}
		record := make([]byte, 312)
		if _, err := io.ReadFull(io.NewSectionReader(file, pos, 312), record); err != nil {
			return nil, true, err
		}
		end := bytes.IndexByte(record[:260], 0)
		if end <= 0 {
			return nil, true, fmt.Errorf("installshield SFX: invalid filename")
		}
		name := strings.ReplaceAll(string(record[:end]), `\`, "/")
		if strings.HasPrefix(name, "/") || strings.Contains(name, ":") || path.Clean(name) != name || name == ".." || strings.HasPrefix(name, "../") {
			return nil, true, fmt.Errorf("installshield SFX: invalid member path %q", name)
		}
		size := int64(binary.LittleEndian.Uint32(record[268:272]))
		for j, b := range record[260:] {
			if j >= 8 && j < 12 {
				continue
			}
			if b != 0 {
				return nil, true, fmt.Errorf("installshield SFX: unsupported file flags for %s", name)
			}
		}
		pos += 312
		if size > file.Size()-pos {
			return nil, true, fmt.Errorf("installshield SFX: truncated payload %s", name)
		}
		key := strings.ToLower("/" + name)
		if archive.files[key] != nil {
			return nil, true, fmt.Errorf("installshield SFX: duplicate file %s", name)
		}
		archive.files[key] = &starfile.Slice{Name: name, Base: file, Offset: pos, Length: size}
		archive.names = append(archive.names, "/"+name)
		pos += size
	}
	archive.size = pos - offset
	return archive, true, nil
}
func (a *sfxArchive) String() string {
	return fmt.Sprintf("<installshield_sfx files=%d>", len(a.names))
}
func (*sfxArchive) Type() string          { return "installshield_sfx" }
func (*sfxArchive) Freeze()               {}
func (*sfxArchive) Truth() starlark.Bool  { return starlark.True }
func (*sfxArchive) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: installshield_sfx") }
func (a *sfxArchive) Get(key starlark.Value) (starlark.Value, bool, error) {
	name, ok := starlark.AsString(key)
	if !ok {
		return nil, false, fmt.Errorf("installshield SFX: path must be string")
	}
	f := a.files[strings.ToLower("/"+strings.TrimPrefix(strings.ReplaceAll(name, `\`, "/"), "/"))]
	return f, f != nil, nil
}
func (*sfxArchive) AttrNames() []string { return []string{"files", "find"} }
func (a *sfxArchive) Attr(name string) (starlark.Value, error) {
	switch name {
	case "files":
		values := []starlark.Value{}
		for _, n := range a.names {
			values = append(values, starlark.String(n))
		}
		return starlark.NewList(values), nil
	case "find":
		return starlark.NewBuiltin("installshield_sfx.find", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var name string
			if err := starlark.UnpackArgs("find", args, kwargs, "path", &name); err != nil {
				return nil, err
			}
			f, found, err := a.Get(starlark.String(name))
			if !found && err == nil {
				return starlark.None, nil
			}
			return f, err
		}), nil
	}
	return nil, nil
}
