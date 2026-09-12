// Package macresource reads classic Macintosh resource forks. Layout follows
// Inside Macintosh: More Macintosh Toolbox, Resource Manager, pp. 1-121–1-125.
// Names and four-byte type codes are retained as bytes, not host filenames.
package macresource

import (
	"encoding/binary"
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
	"sort"
)

type Entry struct {
	Type       [4]byte
	ID         int16
	Name       []byte // nil means unnamed; an empty named resource is distinct.
	Attributes byte
	Compressed bool
	Occurrence int // one-based occurrence of this type/ID in map order
	Offset     int64
	Data       starfile.File
	StoredData starfile.File
}
type Fork struct {
	Attributes   uint16
	Entries      []Entry
	DuplicateIDs bool
}
type span struct{ start, end int64 }

// Open validates the resource map and decodes supported compressed payloads,
// retaining borrowed stored views. It never executes resource code.
func Open(file starfile.File, maximumEntries int) (*Fork, error) {
	return OpenWithLimits(file, maximumEntries, 256<<20)
}

// OpenWithLimits also bounds the total decoded compressed resource bytes.
// Uncompressed resources remain borrowed views; compressed resources are
// validated and decoded in memory, preserving StoredData for inspection.
func OpenWithLimits(file starfile.File, maximumEntries int, maximumDecodedBytes int64) (*Fork, error) {
	if maximumEntries <= 0 {
		return nil, fmt.Errorf("mac resource: maximum_entries must be positive")
	}
	if maximumDecodedBytes < 0 {
		return nil, fmt.Errorf("mac resource: negative decoded size limit")
	}
	be := binary.BigEndian
	var header [16]byte
	if _, err := starfile.ReadFullAt(file, header[:], 0); err != nil {
		return nil, err
	}
	dataOffset, mapOffset := int64(be.Uint32(header[:])), int64(be.Uint32(header[4:]))
	dataSize, mapSize := int64(be.Uint32(header[8:])), int64(be.Uint32(header[12:]))
	valid := func(offset, size int64) bool {
		return offset >= 16 && offset <= file.Size() && size <= file.Size()-offset
	}
	if !valid(dataOffset, dataSize) || !valid(mapOffset, mapSize) || mapSize < 30 || (dataOffset < mapOffset+mapSize && mapOffset < dataOffset+dataSize) {
		return nil, fmt.Errorf("mac resource: invalid data/map ranges")
	}
	// Offsets within the map are 16-bit, but the last reference list can extend
	// beyond 64 KiB. Read records on demand instead of allocating the whole map.
	readMap := func(offset int64, b []byte) error {
		if offset < 0 || offset > mapSize || int64(len(b)) > mapSize-offset {
			return fmt.Errorf("mac resource: map record outside range")
		}
		_, err := starfile.ReadFullAt(file, b, mapOffset+offset)
		return err
	}
	var mapHeader [28]byte
	if err := readMap(0, mapHeader[:]); err != nil {
		return nil, err
	}
	typeOffset, nameOffset := int64(be.Uint16(mapHeader[24:])), int64(be.Uint16(mapHeader[26:]))
	if typeOffset < 28 || nameOffset < 28 || nameOffset > mapSize {
		return nil, fmt.Errorf("mac resource: invalid map list offsets")
	}
	var countBytes [2]byte
	if err := readMap(typeOffset, countBytes[:]); err != nil {
		return nil, err
	}
	typeCount := int(be.Uint16(countBytes[:]))
	if typeCount == 65535 {
		typeCount = 0
	} else {
		typeCount++
	}
	if typeCount > maximumEntries || typeOffset+2+int64(typeCount)*8 > mapSize {
		return nil, fmt.Errorf("mac resource: invalid type count")
	}
	fork := &Fork{Attributes: be.Uint16(mapHeader[22:])}
	seenTypes := map[[4]byte]bool{}
	var ranges []span
	for i := 0; i < typeCount; i++ {
		var typ [8]byte
		if err := readMap(typeOffset+2+int64(i)*8, typ[:]); err != nil {
			return nil, err
		}
		code := [4]byte(typ[:4])
		if seenTypes[code] {
			return nil, fmt.Errorf("mac resource: repeated resource type")
		}
		seenTypes[code] = true
		count := int(be.Uint16(typ[4:])) + 1
		if count > maximumEntries-len(fork.Entries) {
			return nil, fmt.Errorf("mac resource: entry limit exceeded")
		}
		refs := typeOffset + int64(be.Uint16(typ[6:]))
		if refs < typeOffset+2+int64(typeCount)*8 || refs+int64(count)*12 > mapSize {
			return nil, fmt.Errorf("mac resource: invalid reference list")
		}
		ids := map[int16]int{}
		for j := 0; j < count; j++ {
			var ref [12]byte
			if err := readMap(refs+int64(j)*12, ref[:]); err != nil {
				return nil, err
			}
			e := Entry{Type: code, ID: int16(be.Uint16(ref[:])), Attributes: ref[4]}
			ids[e.ID]++
			e.Occurrence = ids[e.ID]
			if e.Occurrence > 1 {
				fork.DuplicateIDs = true
			}
			name := be.Uint16(ref[2:])
			if name != 65535 {
				var n [1]byte
				if err := readMap(nameOffset+int64(name), n[:]); err != nil {
					return nil, err
				}
				e.Name = make([]byte, int(n[0]))
				if err := readMap(nameOffset+int64(name)+1, e.Name); err != nil {
					return nil, err
				}
			}
			relative := int64(ref[5])<<16 | int64(ref[6])<<8 | int64(ref[7])
			if relative > dataSize-4 {
				return nil, fmt.Errorf("mac resource: payload length outside data area")
			}
			var length [4]byte
			if _, err := starfile.ReadFullAt(file, length[:], dataOffset+relative); err != nil {
				return nil, err
			}
			size := int64(be.Uint32(length[:]))
			if size > dataSize-relative-4 {
				return nil, fmt.Errorf("mac resource: payload outside data area")
			}
			e.Offset = dataOffset + relative + 4
			e.Data = &starfile.Slice{Name: fmt.Sprintf("resource %x/%d", code, e.ID), Base: file, Offset: e.Offset, Length: size}
			e.StoredData = e.Data
			ranges = append(ranges, span{relative, relative + 4 + size})
			fork.Entries = append(fork.Entries, e)
		}
	}
	sort.Slice(ranges, func(i, j int) bool { return ranges[i].start < ranges[j].start })
	for i := 1; i < len(ranges); i++ {
		if ranges[i].start < ranges[i-1].end {
			return nil, fmt.Errorf("mac resource: overlapping payloads")
		}
	}
	remaining := maximumDecodedBytes
	for i := range fork.Entries {
		e := &fork.Entries[i]
		if e.Attributes&1 != 0 {
			// Resource Manager checks the tag after the attribute. Several
			// original files retain bit0 on ordinary uncompressed resources.
			// See MacTech 9.1, Resource Compression (1993), loading sequence.
			var tag [4]byte
			if e.StoredData.Size() < 4 {
				continue
			}
			if _, err := starfile.ReadFullAt(e.StoredData, tag[:], 0); err != nil {
				return nil, err
			}
			if be.Uint32(tag[:]) != 0xa89f6572 {
				continue
			}
			decoded, err := decodeCompressed(e.StoredData, maximumDecodedBytes, remaining)
			if err != nil {
				return nil, fmt.Errorf("mac resource %q/%d: %w", e.Type, e.ID, err)
			}
			e.Data = decoded
			e.Compressed = true
			remaining -= decoded.Size()
		}
	}
	return fork, nil
}

func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	maximum := 1000000
	maximumBytes := int64(256 << 20)
	if err := starlark.UnpackArgs("mac_resource", args, kwargs, "file", &value, "maximum_entries?", &maximum, "maximum_decoded_bytes?", &maximumBytes); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("mac resource: expected file")
	}
	fork, err := OpenWithLimits(file, maximum, maximumBytes)
	if err != nil {
		return nil, err
	}
	entries := make([]starlark.Value, len(fork.Entries))
	for i, e := range fork.Entries {
		path := fmt.Sprintf("%x/%d", e.Type, e.ID)
		if e.Occurrence > 1 {
			path += fmt.Sprintf("/%d", e.Occurrence)
		}
		var name starlark.Value = starlark.None
		if e.Name != nil {
			name = starlark.Bytes(e.Name)
		}
		entries[i] = starfile.NewRecord(starlark.StringDict{"resource_type": starlark.Bytes(e.Type[:]), "id": starlark.MakeInt(int(e.ID)), "name": name, "attributes": starlark.MakeInt(int(e.Attributes)), "path": starlark.String(path), "entry_type": starlark.String("file"), "data": e.Data, "size": starlark.MakeInt64(e.Data.Size()), "stored_data": e.StoredData, "stored_size": starlark.MakeInt64(e.StoredData.Size()), "compressed": starlark.Bool(e.Compressed), "offset": starlark.MakeInt64(e.Offset), "occurrence": starlark.MakeInt(e.Occurrence)})
	}
	return starfile.NewRecord(starlark.StringDict{"entries": starlark.NewList(entries), "attributes": starlark.MakeInt(int(fork.Attributes)), "duplicate_ids": starlark.Bool(fork.DuplicateIDs)}), nil
}
