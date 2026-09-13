package ibmisave

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"sync"

	"github.com/tinyrange/trex/auto"
	starfile "github.com/tinyrange/trex/storage/star"
)

// Codes are the external MI type/subtype pairs documented by IBM. Unlisted
// internal types stay numeric; recognizing a name is not decoding its body.
var externalTypes = map[uint16]string{
	0x0701: "*JRNRCV", 0x0e0a: "*USRIDX", 0x0e0c: "*JOBSCD", 0x0e10: "*VLDL",
	0x1901: "*FILE", 0x1903: "*JOBD", 0x1904: "*CLS", 0x1906: "*TBL", 0x1909: "*SBSD", 0x190a: "*DTAARA", 0x1913: "*EXITRG", 0x191a: "*IGCSRT", 0x1933: "*PRDAVL", 0x1934: "*USRSPC",
}

type objectMetadataView struct {
	object         Object
	once           sync.Once
	metadata       map[string]any
	payloads       []auto.Entry
	err            error
	catalog        *objectMetadataView
	catalogEntries map[string][]map[string]any
}

// Share one lazy catalog inspection within each save group. Exact raw names
// and type codes are required: internal companion objects must not inherit the
// metadata of a similarly named external object or a different save group.
func objectViews(objects []Object) map[int64]*objectMetadataView {
	views := make(map[int64]*objectMetadataView, len(objects))
	catalogs := make(map[int][]*objectMetadataView)
	for _, o := range objects {
		v := &objectMetadataView{object: o}
		views[o.Offset] = v
		if o.Type == 0x19db && bytes.HasPrefix(o.RawName, catalogName) {
			catalogs[o.Group] = append(catalogs[o.Group], v)
		}
	}
	for _, v := range views {
		if v.object.Type != 0x19db && len(catalogs[v.object.Group]) == 1 {
			v.catalog = catalogs[v.object.Group][0]
		}
	}
	return views
}

func (v *objectMetadataView) Metadata() (string, map[string]any, error) {
	v.once.Do(v.inspect)
	return "ibmi_object", v.metadata, v.err
}
func (v *objectMetadataView) Entries() ([]auto.Entry, error) {
	v.once.Do(v.inspect)
	if v.err != nil {
		return nil, v.err
	}
	entries, err := rawObjectView(v.object).Entries()
	if err != nil {
		return nil, err
	}
	return append(entries, v.payloads...), nil
}

// textIdentifier handles only the invariant alphabet used by the inspected
// configuration fields, retaining escapes for bytes requiring a national CCSID.
func textIdentifier(b []byte) string {
	s := identifier(b)
	if s == "unnamed" && len(bytes.TrimRight(b, "\x40\x00")) == 0 {
		return ""
	}
	return strings.ReplaceAll(strings.ReplaceAll(s, "%40", " "), "%5C", "*")
}

func (v *objectMetadataView) inspect() {
	o := v.object
	sections := make([]map[string]any, len(o.Sections))
	for i, s := range o.Sections {
		sections[i] = map[string]any{"number": i + 1, "logical_size": s.LogicalSize, "stored_size": s.Data.Size(), "address_hex": fmt.Sprintf("%016x", s.Address)}
	}
	v.metadata = map[string]any{
		"object":          map[string]any{"name": o.Name, "raw_name_hex": fmt.Sprintf("%x", o.RawName), "internal_type_hex": fmt.Sprintf("%04x", o.Type), "external_type": externalTypes[o.Type]},
		"save_descriptor": map[string]any{"offset": o.Offset, "group": o.Group, "release_hex": fmt.Sprintf("%04x", o.Release), "target_release_hex": fmt.Sprintf("%04x", o.TargetRelease), "declared_data_blocks": o.DeclaredDataBlocks, "stored_size": o.Data.Size(), "trailer_size": o.Trailer.Size(), "sections": sections},
		"decoding":        map[string]any{"complete": false, "scope": "save descriptor; object-specific fields are included only where validated"},
	}
	if v.catalog != nil {
		if _, _, err := v.catalog.Metadata(); err != nil {
			v.err = err
			return
		}
		key := fmt.Sprintf("%x:%04x", o.RawName, o.Type)
		if records := v.catalog.catalogEntries[key]; len(records) > 0 {
			v.metadata["catalog_entries"] = records
		}
	}
	if o.Type == 0x0b90 {
		var sources []map[string]any
		for i, s := range o.Sections {
			meta, file, err := sourceRecords(s, i+1)
			if err != nil {
				v.err = err
				return
			}
			if meta != nil {
				sources = append(sources, meta)
			}
			if file != nil {
				v.payloads = append(v.payloads, *file)
			}
		}
		if len(sources) > 0 {
			v.metadata["source_segments"] = sources
		}
	}
	if len(o.Sections) == 0 || o.Sections[0].Data.Size() < 128 {
		return
	}
	f := o.Sections[0].Data
	var h [128]byte
	if _, err := starfile.ReadFullAt(f, h[:], 0); err != nil {
		v.err = err
		return
	}
	be := binary.BigEndian
	// Four inspected database objects begin with other structures. Do not apply
	// the common object header merely because a type is known.
	if be.Uint16(h[0x22:]) != o.Type || !bytes.Equal(h[0x24:0x42], o.RawName) {
		v.metadata["object_header"] = map[string]any{"recognized": false}
		return
	}
	v.metadata["object_header"] = map[string]any{"recognized": true, "section": 1, "offset": 32, "name": textIdentifier(h[0x24:0x42]), "internal_type_hex": fmt.Sprintf("%04x", be.Uint16(h[0x22:])), "prefix_flags_hex": fmt.Sprintf("%x", h[0x20:0x22]), "segment_prefix_hex": fmt.Sprintf("%x", h[:8]), "raw_08_hex": fmt.Sprintf("%x", h[8:16]), "raw_18_hex": fmt.Sprintf("%x", h[0x18:0x20])}
	// The inspected simple-space generation identifies its body with an address
	// exactly one descriptor page beyond the section base. Other address forms
	// require separate decoders, not arbitrary low-bit masking.
	if o.Sections[0].Address > ^uint64(0)-pageSize || be.Uint64(h[0x18:]) != o.Sections[0].Address+pageSize || f.Size() <= pageSize {
		return
	}
	body := &starfile.Slice{Base: f, Offset: pageSize, Length: f.Size() - pageSize}
	v.payloads = append(v.payloads, auto.Entry{Name: "object-space.bin", Kind: "file", Reader: body, Attributes: map[string]any{"section": 1, "offset": pageSize, "interpretation": "stored object space; unknown fields retained"}})
	switch o.Type {
	case 0x19db:
		meta, entries, err := catalogMetadata(body)
		if err != nil {
			v.err = err
			return
		}
		v.metadata["save_catalog"] = meta
		if entries != nil {
			v.payloads = append(v.payloads, *entries)
			records, err := entries.View.Entries()
			if err != nil {
				v.err = err
				return
			}
			v.catalogEntries = make(map[string][]map[string]any, len(records))
			for _, record := range records {
				a := record.Attributes
				a["catalog_descriptor_offset"] = o.Offset
				a["save_group"] = o.Group
				key := a["raw_name_hex"].(string) + ":" + a["internal_type_hex"].(string)
				v.catalogEntries[key] = append(v.catalogEntries[key], a)
			}
		}
	case 0x1906:
		if body.Size() < 256 {
			return
		}
		var table [256]byte
		if _, err := starfile.ReadFullAt(body, table[:], 0); err != nil {
			v.err = err
			return
		}
		mapping := make(map[string]string, 256)
		for i, c := range table {
			mapping[fmt.Sprintf("%02x", i)] = fmt.Sprintf("%02x", c)
		}
		v.metadata["table"] = map[string]any{"byte_mapping": mapping, "section": 1, "offset": pageSize, "length": 256, "remaining_attributes_decoded": false}
		v.payloads = append(v.payloads, auto.Entry{Name: "table.bin", Kind: "file", Reader: &starfile.Slice{Base: body, Length: 256}})
	case 0x190a:
		if body.Size() < 3 {
			return
		}
		var prefix [3]byte
		if _, err := starfile.ReadFullAt(body, prefix[:], 0); err != nil {
			v.err = err
			return
		}
		length := int64(be.Uint16(prefix[1:]))
		if prefix[0]&0x7f != 4 || length > body.Size()-3 {
			v.metadata["data_area"] = map[string]any{"recognized": false, "prefix_hex": fmt.Sprintf("%x", prefix)}
			return
		}
		data := &starfile.Slice{Base: body, Offset: 3, Length: length}
		raw, err := starfile.ReadAll(data)
		if err != nil {
			v.err = err
			return
		}
		v.metadata["data_area"] = map[string]any{"kind": "character", "length": length, "flags_hex": fmt.Sprintf("%02x", prefix[0]), "text_invariant_ebcdic": textIdentifier(raw), "section": 1, "offset": pageSize + 3, "remaining_attributes_decoded": false}
		v.payloads = append(v.payloads, auto.Entry{Name: "value.bin", Kind: "file", Reader: data})
	case 0x1903:
		if body.Size() < 114 {
			return
		}
		var prefix [114]byte
		if _, err := starfile.ReadFullAt(body, prefix[:], 0); err != nil {
			v.err = err
			return
		}
		v.metadata["job_description"] = map[string]any{"user": textIdentifier(prefix[2:12]), "job_queue": textIdentifier(prefix[12:22]), "job_queue_library": textIdentifier(prefix[22:32]), "routing_data": textIdentifier(prefix[34:114]), "priority_bytes_hex": fmt.Sprintf("%x", prefix[32:34]), "section": 1, "offset": pageSize, "decoded_prefix_length": 114, "remaining_attributes_decoded": false}
	}
}
