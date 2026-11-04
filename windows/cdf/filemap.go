package cdf

import (
	"encoding/binary"
	"fmt"
	"github.com/tinyrange/trex/windows/internal/csihash"
	"strings"
	"unicode/utf8"
)

var fileMapFormat = [16]byte{0xff, 0x1b, 0x35, 0x28, 0x25, 0xd5, 0x55, 0x41, 0xac, 0xb0, 0x6e, 0x7c, 0x64, 0xc7, 0x25, 0xd8}

// IdentityAttribute preserves namespace/name/value spelling and attribute order.
// Empty namespace represents the native NoBlob namespace marker.
type IdentityAttribute struct{ Namespace, Name, Value string }

// FileMapEntry is the observed no-hash FileMap record. Identity indexes
// FileMap.Identities; Name is the lookup key, DisplayName the stored file name.
// Flags are preserved, not interpreted as filesystem or servicing permission.
type FileMapEntry struct {
	Name, DisplayName string
	Flags, Identity   uint32
}

type FileMap struct {
	Path         string
	RootSelector uint32
	Identities   [][]IdentityAttribute
	Entries      []FileMapEntry
}

// FileMap resolves the observed no-hash schema. Unknown fields, hash arrays,
// table variants and non-ASCII lookup keys fail closed. No ownership decisions.
func (d *Document) FileMap() (*FileMap, error) {
	if d == nil || d.Format != fileMapFormat || d.Flags != 0 || d.AuxiliaryRoot != NoBlob || len(d.AppIDs) != 0 || len(d.GUIDs) != 0 {
		return nil, fmt.Errorf("FileMap: unsupported container schema")
	}
	blob := func(id uint32, kind uint8) ([]byte, error) {
		if uint64(id) >= uint64(len(d.Blobs)) || d.Blobs[id].Kind != kind {
			return nil, fmt.Errorf("FileMap: invalid kind-%d blob reference %d", kind, id)
		}
		return d.Blobs[id].Data, nil
	}
	textCache := make(map[uint32]string)
	text := func(id uint32) (string, error) {
		if cached, ok := textCache[id]; ok {
			return cached, nil
		}
		if uint64(id) >= uint64(len(d.Strings)) {
			return "", fmt.Errorf("FileMap: invalid string ID %d", id)
		}
		data, e := blob(d.Strings[id], 2)
		if e != nil {
			return "", e
		}
		if !utf8.Valid(data) || strings.IndexByte(string(data), 0) >= 0 {
			return "", fmt.Errorf("FileMap: unsupported string encoding")
		}
		decoded := string(data)
		textCache[id] = decoded
		return decoded, nil
	}
	root, e := blob(d.Root, 9)
	if e != nil {
		return nil, e
	}
	toc, e := ParseTable(9, root)
	if e != nil {
		return nil, e
	}
	if len(toc.Keys) != 2 || toc.Keys[0] != 0 || toc.Keys[1] != 1 {
		return nil, fmt.Errorf("FileMap: unsupported TOC")
	}
	meta, e := blob(toc.Values[1], 1)
	if e != nil {
		return nil, e
	}
	if len(meta) != 8 {
		return nil, fmt.Errorf("FileMap: invalid path metadata")
	}
	out := &FileMap{RootSelector: binary.LittleEndian.Uint32(meta[4:])}
	if out.RootSelector > 2 {
		return nil, fmt.Errorf("FileMap: unsupported root selector")
	}
	if out.Path, e = text(binary.LittleEndian.Uint32(meta[:4])); e != nil {
		return nil, e
	}
	out.Identities = make([][]IdentityAttribute, len(d.Identities))
	totalAttributes := uint64(0)
	for i, id := range d.Identities {
		b, e := blob(id, 4)
		if e != nil {
			return nil, e
		}
		if len(b) < 4 {
			return nil, fmt.Errorf("FileMap: truncated identity")
		}
		n := uint64(binary.LittleEndian.Uint32(b[:4]))
		if n > 1024 || n*12 != uint64(len(b)-4) {
			return nil, fmt.Errorf("FileMap: invalid identity attributes")
		}
		totalAttributes += n
		if totalAttributes > 1<<20 {
			return nil, fmt.Errorf("FileMap: identity attribute limit")
		}
		attrs := make([]IdentityAttribute, int(n))
		seen := make(map[[2]string]bool, len(attrs))
		for j := range attrs {
			off := 4 + 12*j
			ns := binary.LittleEndian.Uint32(b[off : off+4])
			if ns != NoBlob {
				if attrs[j].Namespace, e = text(ns); e != nil {
					return nil, e
				}
			}
			if attrs[j].Name, e = text(binary.LittleEndian.Uint32(b[off+4 : off+8])); e != nil {
				return nil, e
			}
			if attrs[j].Value, e = text(binary.LittleEndian.Uint32(b[off+8 : off+12])); e != nil {
				return nil, e
			}
			key := [2]string{attrs[j].Namespace, strings.ToLower(attrs[j].Name)}
			if seen[key] {
				return nil, fmt.Errorf("FileMap: duplicate identity attribute")
			}
			seen[key] = true
		}
		out.Identities[i] = attrs
	}
	raw, e := blob(toc.Values[0], 6)
	if e != nil {
		return nil, e
	}
	table, e := ParseTable(6, raw)
	if e != nil {
		return nil, e
	}
	out.Entries = make([]FileMapEntry, len(table.Keys))
	names := make(map[string]bool, len(table.Keys))
	for i, k := range table.Keys {
		name, e := text(k)
		if e != nil {
			return nil, e
		}
		hash, e := csihash.Text(name)
		if e != nil {
			return nil, e
		}
		if uint32(hash) != table.Hashes[i] {
			return nil, fmt.Errorf("FileMap: key hash mismatch for %q", name)
		}
		folded := strings.ToLower(name)
		if names[folded] {
			return nil, fmt.Errorf("FileMap: duplicate lookup key %q", name)
		}
		names[folded] = true
		b, e := blob(table.Values[i], 1)
		if e != nil {
			return nil, e
		}
		if len(b) != 28 {
			return nil, fmt.Errorf("FileMap: invalid file record")
		}
		flags := binary.LittleEndian.Uint32(b[:4])
		if flags&^uint32(6) != 0 || binary.LittleEndian.Uint64(b[8:16]) != 0 || binary.LittleEndian.Uint32(b[16:20]) != NoBlob || binary.LittleEndian.Uint32(b[20:24]) != NoBlob {
			return nil, fmt.Errorf("FileMap: unsupported file/hash fields")
		}
		id := binary.LittleEndian.Uint32(b[24:28])
		if uint64(id) >= uint64(len(out.Identities)) {
			return nil, fmt.Errorf("FileMap: invalid file identity")
		}
		display, e := text(binary.LittleEndian.Uint32(b[4:8]))
		if e != nil {
			return nil, e
		}
		if _, e := csihash.Text(display); e != nil {
			return nil, e
		}
		if !strings.EqualFold(name, display) {
			return nil, fmt.Errorf("FileMap: lookup/display name mismatch")
		}
		out.Entries[i] = FileMapEntry{Name: name, DisplayName: display, Flags: flags, Identity: id}
	}
	return out, nil
}
