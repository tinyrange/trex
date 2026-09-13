package ibmisave

import (
	"encoding/binary"
	"fmt"

	"github.com/tinyrange/trex/auto"
	starfile "github.com/tinyrange/trex/storage/star"
	"golang.org/x/text/encoding/charmap"
)

// The inspected 7.5 catalog begins with a 112-byte prefix followed by 151-byte
// entries. The count is a catalog-entry count, NOT a saved-object count: entries
// also describe objects without their own descriptor in this save group.
const catalogPrefixSize = 112
const catalogEntrySize = 151
const catalogEntryLimit = 4096

func catalogMetadata(body starfile.File) (map[string]any, *auto.Entry, error) {
	if body.Size() < catalogPrefixSize {
		return map[string]any{"recognized": false, "reason": "short catalog prefix"}, nil, nil
	}
	var prefix [catalogPrefixSize]byte
	if _, err := starfile.ReadFullAt(body, prefix[:], 0); err != nil {
		return nil, nil, err
	}
	be := binary.BigEndian
	// 024a is an observed layout discriminator, not a length or record stride.
	if be.Uint16(prefix[:]) != 0x024a || be.Uint16(prefix[32:]) != 0x0401 {
		return map[string]any{"recognized": false, "reason": "unsupported catalog prefix"}, nil, nil
	}
	count := int64(be.Uint32(prefix[42:]))
	meta := map[string]any{
		"recognized": true, "library": textIdentifier(prefix[2:32]),
		"library_name_hex": fmt.Sprintf("%x", prefix[2:32]),
		"library_type_hex": "0401", "entry_count": count,
		"section": 1, "offset": pageSize, "entries_offset": pageSize + catalogPrefixSize,
		"entry_size": catalogEntrySize, "remaining_attributes_decoded": false,
	}
	if count > (body.Size()-catalogPrefixSize)/catalogEntrySize {
		meta["entries_decoded"] = false
		meta["reason"] = "catalog entries exceed stored body"
		return meta, nil, nil
	}
	if count > catalogEntryLimit {
		meta["entries_decoded"] = false
		meta["reason"] = "catalog entry inspection limit"
		return meta, nil, nil
	}
	entries := make([]auto.Entry, 0, int(count))
	for i := int64(0); i < count; i++ {
		offset := int64(catalogPrefixSize) + i*catalogEntrySize
		var record [catalogEntrySize]byte
		if _, err := starfile.ReadFullAt(body, record[:], offset); err != nil {
			return nil, nil, err
		}
		typ := be.Uint16(record[30:])
		name := identifier(record[:30])
		description, err := catalogDescription(body, int64(be.Uint32(record[75:])), catalogPrefixSize+count*catalogEntrySize)
		if err != nil {
			return nil, nil, err
		}
		entries = append(entries, auto.Entry{
			Name: fmt.Sprintf("%s.type-%04x.record%d.bin", name, typ, i+1), Kind: "file",
			Reader: &starfile.Slice{Base: body, Offset: offset, Length: catalogEntrySize},
			Attributes: map[string]any{
				"record": i + 1, "section": 1, "offset": pageSize + offset,
				"name": textIdentifier(record[:30]), "raw_name_hex": fmt.Sprintf("%x", record[:30]),
				"internal_type_hex": fmt.Sprintf("%04x", typ), "external_type": externalTypes[typ],
				// This resembles an owning user profile, but that role has not
				// been independently established for all catalog entry types.
				"associated_name":              textIdentifier(record[32:62]),
				"associated_name_hex":          fmt.Sprintf("%x", record[32:62]),
				"description":                  description,
				"remaining_attributes_decoded": false,
			},
		})
	}
	meta["entries_decoded"] = true
	return meta, &auto.Entry{Name: "catalog-entries", Kind: "directory", View: auto.ViewFunc(func() ([]auto.Entry, error) { return entries, nil })}, nil
}

// The referenced attribute block starts with a counted description (0..50
// bytes). Its offset is relative to the space body, not the saved section.
// Other fields in this block are still unknown.
func catalogDescription(body starfile.File, offset, recordsEnd int64) (map[string]any, error) {
	unknown := map[string]any{"decoded": false}
	if offset < recordsEnd || offset > body.Size()-4 {
		return unknown, nil
	}
	var size [4]byte
	if _, err := starfile.ReadFullAt(body, size[:], offset); err != nil {
		return nil, err
	}
	length := int64(binary.BigEndian.Uint32(size[:]))
	if length > 50 || length > body.Size()-offset-4 {
		return unknown, nil
	}
	raw := make([]byte, int(length))
	if _, err := starfile.ReadFullAt(body, raw, offset+4); err != nil {
		return nil, err
	}
	text, err := charmap.CodePage037.NewDecoder().String(string(raw))
	if err != nil {
		return nil, err
	}
	return map[string]any{"decoded": true, "section": 1, "offset": pageSize + offset + 4, "length": length, "raw_hex": fmt.Sprintf("%x", raw), "text": text, "encoding": "IBM037 (explicit rendering, not detected CCSID)"}, nil
}
