package windows

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
	"io"
	"sort"

	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

type peResourceFileEntry struct {
	typ, name, lang string
	offset, size    int64
}

// resource_files explicitly borrows the original source, unlike .resources,
// whose data/text values belong to the PE object's immutable full snapshot.
// Callers must keep original bytes stable for the returned readers' lifetimes.
func (p *windowsPE) resourceFilesBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("resource_files", args, kwargs); err != nil {
		return nil, err
	}
	entries, err := peResourceFiles(p.file)
	if err != nil {
		return nil, err
	}
	result := make([]starlark.Value, 0, len(entries))
	for _, e := range entries {
		value := starlark.NewDict(5)
		for key, item := range map[string]starlark.Value{
			"type": starlark.String(e.typ), "name": starlark.String(e.name), "lang": starlark.String(e.lang), "size": starlark.MakeInt64(e.size),
			"file": starfile.NewReader("PE resource "+e.name, io.NewSectionReader(p.file, e.offset, e.size)),
		} {
			if err := value.SetKey(starlark.String(key), item); err != nil {
				return nil, err
			}
		}
		result = append(result, value)
	}
	value := starlark.NewList(result)
	value.Freeze()
	return value, nil
}
func peResourceFileOffset(pf *pe.File, rva, size uint32) (int64, error) {
	for _, s := range pf.Sections {
		if uint64(rva) < uint64(s.VirtualAddress) {
			continue
		}
		delta := uint64(rva) - uint64(s.VirtualAddress)
		if delta <= uint64(s.Size) && uint64(size) <= uint64(s.Size)-delta {
			return int64(uint64(s.Offset) + delta), nil
		}
	}
	return 0, fmt.Errorf("pe resource: RVA %#x size %d outside raw sections", rva, size)
}
func peResourceFiles(source storage.Reader) ([]peResourceFileEntry, error) {
	pf, err := pe.NewFile(source)
	if err != nil {
		return nil, err
	}
	defer pf.Close()
	var directory pe.DataDirectory
	switch optional := pf.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		directory = optional.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_RESOURCE]
	case *pe.OptionalHeader64:
		directory = optional.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_RESOURCE]
	default:
		return nil, fmt.Errorf("pe resource: unsupported optional header")
	}
	if directory.VirtualAddress == 0 || directory.Size == 0 {
		return nil, nil
	}
	base, err := peResourceFileOffset(pf, directory.VirtualAddress, directory.Size)
	if err != nil {
		return nil, err
	}
	if base < 0 || base > source.Size() || int64(directory.Size) > source.Size()-base {
		return nil, fmt.Errorf("pe resource: directory outside file")
	}
	read := func(relative uint64, size int) ([]byte, error) {
		if size < 0 || relative > uint64(directory.Size) || uint64(size) > uint64(directory.Size)-relative {
			return nil, fmt.Errorf("pe resource: metadata outside directory")
		}
		data := make([]byte, size)
		if _, err := io.ReadFull(io.NewSectionReader(source, base+int64(relative), int64(size)), data); err != nil {
			return nil, err
		}
		return data, nil
	}
	name := func(raw uint32) (string, error) {
		if raw&0x80000000 == 0 {
			return fmt.Sprintf("#%d", raw), nil
		}
		off := uint64(raw & 0x7fffffff)
		length, err := read(off, 2)
		if err != nil {
			return "", err
		}
		data, err := read(off+2, 2*int(binary.LittleEndian.Uint16(length)))
		if err != nil {
			return "", err
		}
		return decodeUTF16LE(data), nil
	}
	var result []peResourceFileEntry
	active := make(map[uint32]bool)
	visited := 0
	var walk func(uint32, []string) error
	walk = func(relative uint32, path []string) error {
		if len(path) > 16 || active[relative] {
			return fmt.Errorf("pe resource: cyclic or excessive directory depth")
		}
		active[relative] = true
		defer delete(active, relative)
		header, err := read(uint64(relative), 16)
		if err != nil {
			return err
		}
		count := int(binary.LittleEndian.Uint16(header[12:])) + int(binary.LittleEndian.Uint16(header[14:]))
		if count > 65536-visited {
			return fmt.Errorf("pe resource: too many directory entries")
		}
		visited += count
		table, err := read(uint64(relative)+16, count*8)
		if err != nil {
			return err
		}
		for i := 0; i < count; i++ {
			entry := table[i*8:]
			label, err := name(binary.LittleEndian.Uint32(entry))
			if err != nil {
				return err
			}
			child := binary.LittleEndian.Uint32(entry[4:])
			off := child & 0x7fffffff
			next := append(append([]string(nil), path...), label)
			if child&0x80000000 != 0 {
				if err := walk(off, next); err != nil {
					return err
				}
				continue
			}
			descriptor, err := read(uint64(off), 16)
			if err != nil {
				return err
			}
			rva, size := binary.LittleEndian.Uint32(descriptor), binary.LittleEndian.Uint32(descriptor[4:])
			offset, err := peResourceFileOffset(pf, rva, size)
			if err != nil {
				return err
			}
			if offset < 0 || offset > source.Size() || int64(size) > source.Size()-offset {
				return fmt.Errorf("pe resource: data outside file")
			}
			row := peResourceFileEntry{offset: offset, size: int64(size)}
			if len(next) > 0 {
				row.typ = next[0]
			}
			if len(next) > 1 {
				row.name = next[1]
			}
			if len(next) > 2 {
				row.lang = next[2]
			}
			result = append(result, row)
		}
		return nil
	}
	if err := walk(0, nil); err != nil {
		return nil, err
	}
	sort.Slice(result, func(i, j int) bool {
		a, b := result[i], result[j]
		if a.typ != b.typ {
			return a.typ < b.typ
		}
		if a.name != b.name {
			return a.name < b.name
		}
		return a.lang < b.lang
	})
	return result, nil
}
