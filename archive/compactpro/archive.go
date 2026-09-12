package compactpro

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"sort"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

type Entry struct {
	Path                                       string
	Name                                       []byte
	Directory                                  bool
	Type, Creator                              [4]byte
	Created, Modified                          uint32
	FinderFlags, Flags                         uint16
	CRC                                        uint32
	Data, Resource, StoredData, StoredResource starfile.File
}
type Archive struct {
	Comment  []byte
	Volume   byte
	VolumeID uint16
	Entries  []Entry
}

// Open verifies the catalog and both decoded forks of every file. Bytes remain
// in memory; names retain their original encoding and paths use reversible
// percent escapes. maximumBytes bounds total decoded forks and each input fork.
func Open(file starfile.File, maximumEntries int, maximumBytes int64) (*Archive, error) {
	if maximumEntries <= 0 || maximumBytes < 0 {
		return nil, fmt.Errorf("compactpro: invalid limits")
	}
	var h [8]byte
	if _, err := starfile.ReadFullAt(file, h[:], 0); err != nil {
		return nil, err
	}
	if h[0] != 1 || h[1] != 1 {
		return nil, fmt.Errorf("compactpro: invalid signature or unsupported multi-volume archive")
	}
	be := binary.BigEndian
	catalog := int64(be.Uint32(h[4:]))
	if catalog < 8 || catalog > file.Size()-7 {
		return nil, fmt.Errorf("compactpro: catalog outside input")
	}
	// Catalog sizes are bounded by the 16-bit entry count and maximum name
	// and record lengths, independently of declared decoded payload sizes.
	if file.Size()-catalog > 7+255+65535*(128+45) {
		return nil, fmt.Errorf("compactpro: catalog too large")
	}
	b, err := starfile.ReadAll(&starfile.Slice{Base: file, Offset: catalog, Length: file.Size() - catalog})
	if err != nil {
		return nil, err
	}
	if ^crc32.ChecksumIEEE(b[4:]) != be.Uint32(b) {
		return nil, fmt.Errorf("compactpro: catalog CRC mismatch")
	}
	count := int(be.Uint16(b[4:]))
	if count > maximumEntries {
		return nil, fmt.Errorf("compactpro: entry limit exceeded")
	}
	a := &Archive{Volume: h[1], VolumeID: be.Uint16(h[2:])}
	pos := 7
	take := func(n int) ([]byte, error) {
		if n < 0 || n > len(b)-pos {
			return nil, io.ErrUnexpectedEOF
		}
		v := b[pos : pos+n]
		pos += n
		return v, nil
	}
	a.Comment, err = take(int(b[6]))
	if err != nil {
		return nil, err
	}
	type directory struct {
		path string
		end  int
	}
	stack := []directory{{"", count}}
	type payload struct{ offset, rs, ds, ru, du int64 }
	var payloads []payload
	type span struct{ start, end int64 }
	var spans []span
	seen := map[string]bool{}
	remaining := maximumBytes
	for i := 0; i < count; i++ {
		for len(stack) > 1 && i == stack[len(stack)-1].end {
			stack = stack[:len(stack)-1]
		}
		kind, err := take(1)
		if err != nil {
			return nil, err
		}
		name, err := take(int(kind[0] & 127))
		if err != nil {
			return nil, err
		}
		if len(name) == 0 {
			return nil, fmt.Errorf("compactpro: empty entry name")
		}
		e := Entry{Name: append([]byte{}, name...), Directory: kind[0]&128 != 0, Path: stack[len(stack)-1].path + "/" + component(name)}
		if seen[e.Path] {
			return nil, fmt.Errorf("compactpro: duplicate path %q", e.Path)
		}
		seen[e.Path] = true
		p := payload{}
		if e.Directory {
			v, err := take(2)
			if err != nil {
				return nil, err
			}
			end := i + 1 + int(be.Uint16(v))
			if end > stack[len(stack)-1].end {
				return nil, fmt.Errorf("compactpro: directory exceeds parent range")
			}
			if end > i+1 {
				stack = append(stack, directory{e.Path, end})
			}
		} else {
			v, err := take(45)
			if err != nil {
				return nil, err
			}
			if v[0] != 1 {
				return nil, fmt.Errorf("compactpro: file requires another volume")
			}
			p.offset = int64(be.Uint32(v[1:]))
			copy(e.Type[:], v[5:9])
			copy(e.Creator[:], v[9:13])
			e.Created = be.Uint32(v[13:])
			e.Modified = be.Uint32(v[17:])
			e.FinderFlags = be.Uint16(v[21:])
			e.CRC = be.Uint32(v[23:])
			e.Flags = be.Uint16(v[27:])
			if e.Flags & ^uint16(6) != 0 {
				return nil, fmt.Errorf("compactpro: encrypted or unknown flags %04x", e.Flags)
			}
			p.ru = int64(be.Uint32(v[29:]))
			p.du = int64(be.Uint32(v[33:]))
			p.rs = int64(be.Uint32(v[37:]))
			p.ds = int64(be.Uint32(v[41:]))
			if p.offset < 8 || p.offset > catalog || p.rs+p.ds > catalog-p.offset {
				return nil, fmt.Errorf("compactpro: payload outside data area")
			}
			if p.ru+p.du > remaining || p.rs > maximumBytes || p.ds > maximumBytes {
				return nil, fmt.Errorf("compactpro: decoded or stored fork limit exceeded")
			}
			if p.ru >= int64(int(^uint(0)>>1)) || p.du >= int64(int(^uint(0)>>1)) {
				return nil, fmt.Errorf("compactpro: fork exceeds address space")
			}
			remaining -= p.ru + p.du
			if p.rs+p.ds > 0 {
				spans = append(spans, span{p.offset, p.offset + p.rs + p.ds})
			}
		}
		a.Entries = append(a.Entries, e)
		payloads = append(payloads, p)
	}
	if pos != len(b) {
		return nil, fmt.Errorf("compactpro: trailing catalog bytes")
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })
	for i := 1; i < len(spans); i++ {
		if spans[i].start < spans[i-1].end {
			return nil, fmt.Errorf("compactpro: overlapping file payloads")
		}
	}
	for i := range a.Entries {
		e, p := &a.Entries[i], payloads[i]
		if e.Directory {
			continue
		}
		e.StoredResource = &starfile.Slice{Name: e.Path + ":stored resource", Base: file, Offset: p.offset, Length: p.rs}
		e.StoredData = &starfile.Slice{Name: e.Path + ":stored data", Base: file, Offset: p.offset + p.rs, Length: p.ds}
		forks := []struct {
			source starfile.File
			size   int64
			lzh    bool
		}{{e.StoredResource, p.ru, e.Flags&2 != 0}, {e.StoredData, p.du, e.Flags&4 != 0}}
		crc := crc32.NewIEEE()
		for j, fork := range forks {
			input, err := starfile.ReadAll(fork.source)
			if err != nil {
				return nil, err
			}
			decoded, err := decode(input, int(fork.size), fork.lzh)
			if err != nil {
				return nil, fmt.Errorf("compactpro %q fork %d: %w", e.Path, j, err)
			}
			crc.Write(decoded)
			value := &starfile.Bytes{Name: e.Path, Data: decoded}
			if j == 0 {
				e.Resource = value
			} else {
				e.Data = value
			}
		}
		if ^crc.Sum32() != e.CRC {
			return nil, fmt.Errorf("compactpro %q: decoded forks CRC mismatch", e.Path)
		}
	}
	return a, nil
}

func component(name []byte) string {
	const digits = "0123456789ABCDEF"
	var b []byte
	for _, v := range name {
		if v < 32 || v >= 127 || v == '/' || v == '%' || (string(name) == "." || string(name) == "..") {
			b = append(b, '%', digits[v>>4], digits[v&15])
		} else {
			b = append(b, v)
		}
	}
	return string(b)
}
func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	maximumEntries, maximumBytes := 1000000, int64(256<<20)
	if err := starlark.UnpackArgs("compactpro", args, kwargs, "file", &value, "maximum_entries?", &maximumEntries, "maximum_decoded_bytes?", &maximumBytes); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("compactpro: expected file")
	}
	a, err := Open(file, maximumEntries, maximumBytes)
	if err != nil {
		return nil, err
	}
	entries := make([]starlark.Value, len(a.Entries))
	for i, e := range a.Entries {
		kind := "file"
		if e.Directory {
			kind = "directory"
		}
		attrs := starlark.StringDict{"path": starlark.String(e.Path), "name": starlark.Bytes(e.Name), "entry_type": starlark.String(kind), "size": starlark.MakeInt(0), "resource_size": starlark.MakeInt(0)}
		if !e.Directory {
			attrs["data"], attrs["resource"], attrs["stored_data"], attrs["stored_resource"] = e.Data, e.Resource, e.StoredData, e.StoredResource
			attrs["size"], attrs["resource_size"] = starlark.MakeInt64(e.Data.Size()), starlark.MakeInt64(e.Resource.Size())
			attrs["file_type"], attrs["creator"] = starlark.Bytes(e.Type[:]), starlark.Bytes(e.Creator[:])
			attrs["created"], attrs["modified"] = starlark.MakeUint(uint(e.Created)), starlark.MakeUint(uint(e.Modified))
			attrs["flags"], attrs["finder_flags"], attrs["crc32"] = starlark.MakeInt(int(e.Flags)), starlark.MakeInt(int(e.FinderFlags)), starlark.MakeUint(uint(e.CRC))
		}
		entries[i] = starfile.NewRecord(attrs)
	}
	return starfile.NewRecord(starlark.StringDict{"entries": starlark.NewList(entries), "comment": starlark.Bytes(a.Comment), "volume": starlark.MakeInt(int(a.Volume)), "volume_id": starlark.MakeInt(int(a.VolumeID))}), nil
}
