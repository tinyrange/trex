package irix

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

// TapeEntry describes one file in an SGI standalone tape directory. Offsets
// are 512-byte block addresses; sizes exclude final block padding.
type TapeEntry struct {
	Name   string
	Offset int64
	Data   starfile.File
}

// OpenTape reads the checksummed 512-byte standalone directory, not an inst
// product image. Its twenty slots each hold a 16-byte name, block and size.
// Members remain borrowed file views, including miniroot filesystem images.
func OpenTape(file starfile.File) ([]TapeEntry, error) {
	var header [512]byte
	if _, err := starfile.ReadFullAt(file, header[:], 0); err != nil {
		return nil, err
	}
	be := binary.BigEndian
	if be.Uint32(header[:]) != 0xaced1234 {
		return nil, fmt.Errorf("irix tape: invalid standalone directory signature")
	}
	var sum uint32
	for off := 0; off < len(header); off += 4 {
		sum += be.Uint32(header[off:])
	}
	if sum != 0 {
		return nil, fmt.Errorf("irix tape: invalid directory checksum")
	}
	var entries []TapeEntry
	seen := map[string]bool{}
	for off := 32; off < len(header); off += 24 {
		slot := header[off : off+24]
		if slot[0] == 0 {
			continue
		}
		nameBytes := slot[:16]
		if end := bytes.IndexByte(nameBytes, 0); end >= 0 {
			nameBytes = nameBytes[:end]
		}
		name := string(nameBytes)
		if strings.Contains(name, "/") || name == "." || name == ".." || seen[name] {
			return nil, fmt.Errorf("irix tape: invalid or repeated name %q", name)
		}
		start := int64(be.Uint32(slot[16:])) * 512
		size := int64(be.Uint32(slot[20:]))
		if start < 512 || start > file.Size() || size > file.Size()-start {
			return nil, fmt.Errorf("irix tape: member %s outside input", name)
		}
		for _, previous := range entries {
			if start < previous.Offset+previous.Data.Size() && previous.Offset < start+size {
				return nil, fmt.Errorf("irix tape: overlapping member %s", name)
			}
		}
		seen[name] = true
		entries = append(entries, TapeEntry{Name: name, Offset: start, Data: &starfile.Slice{Name: name, Base: file, Offset: start, Length: size}})
	}
	return entries, nil
}

func TapeBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("irix_tape", args, kwargs, "file", &value); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("irix tape: expected file")
	}
	entries, err := OpenTape(file)
	if err != nil {
		return nil, err
	}
	values := make([]starlark.Value, len(entries))
	for i, entry := range entries {
		values[i] = starfile.NewRecord(starlark.StringDict{
			"path": starlark.String(entry.Name), "entry_type": starlark.String("file"),
			"size": starlark.MakeInt64(entry.Data.Size()), "offset": starlark.MakeInt64(entry.Offset), "data": entry.Data,
		})
	}
	return starfile.NewRecord(starlark.StringDict{"entries": starlark.NewList(values)}), nil
}
