// Package tome reads classic Apple installer Tome catalogs and fork payloads.
package tome

import (
	"encoding/binary"
	"fmt"
	"math/bits"
	"sort"

	"github.com/tinyrange/trex/archive/internal/instacomp"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

type Entry struct {
	ResourceID                                 int16
	ResourceType                               [4]byte
	ID                                         uint16
	Name                                       []byte
	Path                                       string
	Type, Creator                              [4]byte
	Created, Modified, FinderFlags             uint32
	Version                                    uint16
	DataChecksum, ResourceChecksum             uint32
	Data, Resource, StoredData, StoredResource starfile.File
}
type Archive struct {
	Kind    uint16
	Entries []Entry
}

// Open reads both forks without executing installer code. maximumBytes bounds
// total decoded bytes and each stored fork. Both decoded fork checksums are
// verified before exposing entries.
// Catalog field locations agree with the MIT-licensed TomeViewerX metadata
// research: https://github.com/kainjow/TomeViewerX . Payload framing is based on
// direct inspection of original Apple installer media.
func Open(file starfile.File, maximumEntries int, maximumBytes int64) (*Archive, error) {
	if maximumEntries <= 0 || maximumBytes < 0 {
		return nil, fmt.Errorf("tome: invalid limits")
	}
	var h [36]byte
	if _, err := starfile.ReadFullAt(file, h[:], 0); err != nil {
		return nil, err
	}
	be := binary.BigEndian
	if be.Uint32(h[:]) != 0x6b630001 {
		return nil, fmt.Errorf("tome: unsupported signature")
	}
	kind := be.Uint16(h[16:])
	if kind != 1 && kind != 2 {
		return nil, fmt.Errorf("tome: unsupported catalog kind %d", kind)
	}
	// Offset28 tracks the ID range, not the number of live records. Deleted
	// or split catalogs have gaps (e.g. IDs4,5,6 with only three records).
	count := int64(be.Uint16(h[26:]))
	catalogEnd := int64(36) + count*128
	if count > int64(maximumEntries) || catalogEnd > file.Size() {
		return nil, fmt.Errorf("tome: catalog count outside limits or input")
	}
	a := &Archive{Kind: kind}
	type fork struct{ offset, stored, size int64 }
	type span struct{ start, end int64 }
	var forks [][2]fork
	var spans []span
	seen := map[uint16]bool{}
	remaining := maximumBytes
	for i := int64(0); i < count; i++ {
		var b [128]byte
		if _, err := starfile.ReadFullAt(file, b[:], 36+i*128); err != nil {
			return nil, err
		}
		id := be.Uint16(b[4:])
		nameOffset, nameMaximum := 6, 31
		if kind == 2 {
			nameOffset, nameMaximum = 12, 63
		}
		if seen[id] || (kind == 1 && b[nameOffset] == 0) || int(b[nameOffset]) > nameMaximum {
			return nil, fmt.Errorf("tome: duplicate ID or invalid name at record %d", i)
		}
		seen[id] = true
		e := Entry{ID: id, Name: append([]byte{}, b[nameOffset+1:nameOffset+1+int(b[nameOffset])]...)}
		if kind == 1 {
			e.Created, e.Modified = be.Uint32(b[46:]), be.Uint32(b[50:])
			e.Version, e.FinderFlags = be.Uint16(b[54:]), be.Uint32(b[56:])
			e.DataChecksum, e.ResourceChecksum = be.Uint32(b[72:]), be.Uint32(b[88:])
			copy(e.Type[:], b[38:42])
			copy(e.Creator[:], b[42:46])
		} else {
			e.ResourceID = int16(be.Uint16(b[6:]))
			copy(e.ResourceType[:], b[8:12])
			e.DataChecksum = be.Uint32(b[90:])
		}
		// Tome IDs are the installer identity; equal display names need not
		// represent the same file. Preserve both without inventing directories.
		e.Path = fmt.Sprintf("/%d/%s", id, component(e.Name))
		if kind == 2 && len(e.Name) == 0 {
			e.Path = fmt.Sprintf("/%d/%x/%d", id, e.ResourceType, e.ResourceID)
		}
		var fs [2]fork
		for j, offset := range []int{60, 76} {
			if kind == 2 {
				if j == 1 {
					continue
				}
				offset = 78
			}
			f := fork{size: int64(be.Uint32(b[offset:])), offset: int64(be.Uint32(b[offset+4:])), stored: int64(be.Uint32(b[offset+8:]))}
			if f.size > remaining || f.stored > maximumBytes || f.size >= int64(int(^uint(0)>>1)) {
				return nil, fmt.Errorf("tome: fork limit exceeded")
			}
			remaining -= f.size
			if f.stored == 0 {
				if f.size != 0 {
					return nil, fmt.Errorf("tome: missing nonempty fork")
				}
			} else {
				if f.offset < catalogEnd || f.offset > file.Size() || f.stored > file.Size()-f.offset {
					return nil, fmt.Errorf("tome: fork outside payload area")
				}
				spans = append(spans, span{f.offset, f.offset + f.stored})
			}
			fs[j] = f
		}
		forks = append(forks, fs)
		a.Entries = append(a.Entries, e)
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })
	for i := 1; i < len(spans); i++ {
		if spans[i].start < spans[i-1].end {
			return nil, fmt.Errorf("tome: overlapping forks")
		}
	}
	for i, fs := range forks {
		var stored, decoded [2]starfile.File
		for j, f := range fs {
			stored[j] = &starfile.Slice{Base: file, Offset: f.offset, Length: f.stored}
			input, err := starfile.ReadAll(stored[j])
			if err != nil {
				return nil, err
			}
			out, err := decodeFork(input, int(f.size))
			if err != nil {
				return nil, fmt.Errorf("tome: ID %d fork %d: %w", a.Entries[i].ID, j, err)
			}
			want := a.Entries[i].DataChecksum
			if j == 1 {
				want = a.Entries[i].ResourceChecksum
			}
			if checksum(out) != want {
				return nil, fmt.Errorf("tome: ID %d fork %d: checksum mismatch", a.Entries[i].ID, j)
			}
			decoded[j] = &starfile.Bytes{Name: a.Entries[i].Path, Data: out}
		}
		e := &a.Entries[i]
		e.StoredData, e.StoredResource = stored[0], stored[1]
		e.Data, e.Resource = decoded[0], decoded[1]
	}
	return a, nil
}

func decodeFork(input []byte, size int) ([]byte, error) {
	var out []byte
	pos := 0
	target := 0
	for len(out) < size {
		if len(input)-pos < 4 {
			return nil, fmt.Errorf("truncated chunk header")
		}
		mode := binary.BigEndian.Uint32(input[pos:])
		stored := input[pos] == 1
		if !stored && mode != 65536 && mode != 0 {
			return nil, fmt.Errorf("unsupported chunk header %08x at %d", binary.BigEndian.Uint32(input[pos:]), pos)
		}
		pos += 4
		var n int
		var err error
		// Boundaries are absolute multiples, even when the preceding command
		// crossed one. Do not accumulate the previous block's overshoot.
		target += min(65536, size-target)
		if stored {
			// Only the leading byte selects stored mode. The remaining bytes
			// can contain residual state, as on the original Mac7.6 CD.
			n = target - len(out)
			if n > len(input)-pos {
				return nil, fmt.Errorf("truncated stored chunk")
			}
			out = append(out, input[pos:pos+n]...)
		} else if mode == 0 {
			out, n, err = instacomp.DecodeASCII(input[pos:], out, target, size)
		} else {
			out, n, err = instacomp.Decode(input[pos:], out, target, size, 32768)
		}
		if err != nil {
			return nil, err
		}
		pos += n
	}
	if pos != len(input) {
		return nil, fmt.Errorf("trailing fork bytes: consumed %d of %d", pos, len(input))
	}
	return out, nil
}

// Original CalcChecksumFromDataPtr rotates by one byte and XORs a sign-extended
// byte. It is not a CRC. Absent forks use zero instead of the initial state.
func checksum(data []byte) uint32 {
	if len(data) == 0 {
		return 0
	}
	c := uint32(0xffffffff)
	for _, v := range data {
		c = bits.RotateLeft32(c, 8) ^ uint32(int32(int8(v)))
	}
	return c
}

func component(name []byte) string {
	b := []byte{}
	for _, c := range name {
		if c <= 32 || c >= 127 || c == '/' || c == '%' {
			b = append(b, fmt.Sprintf("%%%02X", c)...)
		} else {
			b = append(b, c)
		}
	}
	return string(b)
}

func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	maximumEntries, maximumBytes := 1000000, int64(256<<20)
	if err := starlark.UnpackArgs("tome", args, kwargs, "file", &value, "maximum_entries?", &maximumEntries, "maximum_decoded_bytes?", &maximumBytes); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("tome: expected file")
	}
	a, err := Open(file, maximumEntries, maximumBytes)
	if err != nil {
		return nil, err
	}
	entries := make([]starlark.Value, len(a.Entries))
	for i, e := range a.Entries {
		attrs := starlark.StringDict{
			"id": starlark.MakeInt(int(e.ID)), "path": starlark.String(e.Path), "name": starlark.Bytes(e.Name), "entry_type": starlark.String("file"),
			"data": e.Data, "resource": e.Resource, "stored_data": e.StoredData, "stored_resource": e.StoredResource,
			"size": starlark.MakeInt64(e.Data.Size()), "resource_size": starlark.MakeInt64(e.Resource.Size()),
			"file_type": starlark.Bytes(e.Type[:]), "creator": starlark.Bytes(e.Creator[:]), "created": starlark.MakeUint(uint(e.Created)), "modified": starlark.MakeUint(uint(e.Modified)),
			"version": starlark.MakeInt(int(e.Version)), "finder_flags": starlark.MakeUint(uint(e.FinderFlags)), "data_checksum": starlark.MakeUint(uint(e.DataChecksum)), "resource_checksum": starlark.MakeUint(uint(e.ResourceChecksum)),
		}
		if a.Kind == 2 {
			for _, name := range []string{"file_type", "creator", "created", "modified", "version", "finder_flags"} {
				delete(attrs, name)
			}
			attrs["resource_type"] = starlark.Bytes(e.ResourceType[:])
			attrs["resource_id"] = starlark.MakeInt(int(e.ResourceID))
		}
		entries[i] = starfile.NewRecord(attrs)
	}
	return starfile.NewRecord(starlark.StringDict{"entries": starlark.NewList(entries), "checksums_verified": starlark.True, "catalog_kind": starlark.MakeInt(int(a.Kind))}), nil
}
