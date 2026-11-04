package cdf

import (
	"encoding/binary"
	"fmt"
	"github.com/tinyrange/trex/windows/internal/csihash"
	"sort"
	"strings"
	"unicode/utf8"
)

// Marshal rebuilds the supported no-hash FileMap schema, interning strings and
// retaining only referenced identities. IDs/layout may change; resolved records
// do not. Equal-hash table keys retain input order. Empty maps are unsupported:
// deciding whether to delete a map belongs to servicing policy, not this writer.
func (m *FileMap) Marshal() ([]byte, error) {
	if m == nil || m.RootSelector > 2 || len(m.Entries) == 0 || len(m.Entries) > 1<<20 || len(m.Identities) > 1<<20 {
		return nil, fmt.Errorf("FileMap: invalid dimensions or root")
	}
	d := &Document{Format: fileMapFormat, AuxiliaryRoot: NoBlob}
	total := 0
	addBlob := func(kind uint8, data []byte) (uint32, error) {
		if len(d.Blobs) >= 1<<20 || len(data) > 0xffffff || len(data) > MaxSize-total {
			return 0, fmt.Errorf("FileMap: payload limit")
		}
		total += len(data)
		id := uint32(len(d.Blobs))
		d.Blobs = append(d.Blobs, Blob{Kind: kind, Data: data})
		return id, nil
	}
	stringsByText := make(map[string]uint32)
	intern := func(s string) (uint32, error) {
		if id, ok := stringsByText[s]; ok {
			return id, nil
		}
		if !utf8.ValidString(s) || strings.IndexByte(s, 0) >= 0 {
			return 0, fmt.Errorf("FileMap: unsupported string encoding")
		}
		if len(s) > 0xffffff || len(s) > MaxSize-total {
			return 0, fmt.Errorf("FileMap: string limit")
		}
		id, e := addBlob(2, []byte(s))
		if e != nil {
			return 0, e
		}
		sid := uint32(len(d.Strings))
		d.Strings = append(d.Strings, id)
		stringsByText[s] = sid
		return sid, nil
	}
	identities := make(map[uint32]uint32)
	attrsTotal := 0
	identity := func(old uint32) (uint32, error) {
		if id, ok := identities[old]; ok {
			return id, nil
		}
		if uint64(old) >= uint64(len(m.Identities)) {
			return 0, fmt.Errorf("FileMap: missing identity")
		}
		attrs := m.Identities[old]
		if len(attrs) > 1024 || len(attrs) > (1<<20)-attrsTotal {
			return 0, fmt.Errorf("FileMap: identity attribute limit")
		}
		attrsTotal += len(attrs)
		raw := make([]byte, 4+12*len(attrs))
		binary.LittleEndian.PutUint32(raw, uint32(len(attrs)))
		seen := make(map[[2]string]bool, len(attrs))
		for j, a := range attrs {
			key := [2]string{a.Namespace, strings.ToLower(a.Name)}
			if seen[key] {
				return 0, fmt.Errorf("FileMap: duplicate identity attribute")
			}
			seen[key] = true
			ns := NoBlob
			var e error
			if a.Namespace != "" {
				if ns, e = intern(a.Namespace); e != nil {
					return 0, e
				}
			}
			name, e := intern(a.Name)
			if e != nil {
				return 0, e
			}
			value, e := intern(a.Value)
			if e != nil {
				return 0, e
			}
			for k, v := range []uint32{ns, name, value} {
				binary.LittleEndian.PutUint32(raw[4+12*j+4*k:], v)
			}
		}
		blob, e := addBlob(4, raw)
		if e != nil {
			return 0, e
		}
		id := uint32(len(d.Identities))
		d.Identities = append(d.Identities, blob)
		identities[old] = id
		return id, nil
	}
	type row struct{ hash, key, value uint32 }
	rows := make([]row, len(m.Entries))
	seen := make(map[string]bool, len(rows))
	for i, f := range m.Entries {
		if f.Flags&^uint32(6) != 0 || !strings.EqualFold(f.Name, f.DisplayName) {
			return nil, fmt.Errorf("FileMap: unsupported file record")
		}
		if _, e := csihash.Text(f.DisplayName); e != nil {
			return nil, e
		}
		hash, e := csihash.Text(f.Name)
		if e != nil {
			return nil, e
		}
		folded := strings.ToLower(f.Name)
		if seen[folded] {
			return nil, fmt.Errorf("FileMap: duplicate key")
		}
		seen[folded] = true
		key, e := intern(f.Name)
		if e != nil {
			return nil, e
		}
		display, e := intern(f.DisplayName)
		if e != nil {
			return nil, e
		}
		owner, e := identity(f.Identity)
		if e != nil {
			return nil, e
		}
		raw := make([]byte, 28)
		for j, v := range []uint32{f.Flags, display, 0, 0, NoBlob, NoBlob, owner} {
			binary.LittleEndian.PutUint32(raw[4*j:], v)
		}
		id, e := addBlob(1, raw)
		if e != nil {
			return nil, e
		}
		rows[i] = row{uint32(hash), key, id}
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].hash < rows[j].hash })
	table := &Table{Kind: 6}
	for _, r := range rows {
		table.Hashes = append(table.Hashes, r.hash)
		table.Keys = append(table.Keys, r.key)
		table.Values = append(table.Values, r.value)
	}
	raw, e := table.Marshal()
	if e != nil {
		return nil, e
	}
	files, e := addBlob(6, raw)
	if e != nil {
		return nil, e
	}
	path, e := intern(m.Path)
	if e != nil {
		return nil, e
	}
	raw = make([]byte, 8)
	binary.LittleEndian.PutUint32(raw, path)
	binary.LittleEndian.PutUint32(raw[4:], m.RootSelector)
	meta, e := addBlob(1, raw)
	if e != nil {
		return nil, e
	}
	toc := &Table{Kind: 9, Keys: []uint32{0, 1}, Values: []uint32{files, meta}}
	raw, e = toc.Marshal()
	if e != nil {
		return nil, e
	}
	d.Root, e = addBlob(9, raw)
	if e != nil {
		return nil, e
	}
	return d.Marshal()
}
