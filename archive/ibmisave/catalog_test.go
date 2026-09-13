package ibmisave

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
)

func catalogFixture(t *testing.T, count int) []byte {
	t.Helper()
	b := make([]byte, catalogPrefixSize+count*catalogEntrySize)
	binary.BigEndian.PutUint16(b, 0x024a)
	putText(t, b[2:32], "QGPL")
	binary.BigEndian.PutUint16(b[32:], 0x0401)
	binary.BigEndian.PutUint32(b[42:], uint32(count))
	for i := range count {
		r := b[catalogPrefixSize+i*catalogEntrySize:]
		putText(t, r[:30], "QBATCH")
		binary.BigEndian.PutUint16(r[30:], 0x1904)
		putText(t, r[32:62], "QPGMR")
	}
	return b
}

func TestCatalogAssociationUsesGroupNameAndType(t *testing.T) {
	catalog := objectFixture(t, 0x19db)
	catalog.Group = 1
	putText(t, catalog.RawName, "QSRDSSPC.1")
	copy(catalog.Data.(*starfile.Bytes).Data[0x24:], catalog.RawName)
	copy(catalog.Data.(*starfile.Bytes).Data[4096:], catalogFixture(t, 2))
	var objects = []Object{catalog}
	for i := range 3 {
		o := objectFixture(t, 0x1904)
		o.Group = 1
		o.Offset = int64((i + 1) * 8192)
		putText(t, o.RawName, "QBATCH")
		copy(o.Data.(*starfile.Bytes).Data[0x24:], o.RawName)
		if i == 1 {
			o.Group = 2
		}
		if i == 2 {
			o.Type = 0x1903
		}
		objects = append(objects, o)
	}
	views := objectViews(objects)
	for i, o := range objects[1:] {
		_, m, err := views[o.Offset].Metadata()
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			if len(m["catalog_entries"].([]map[string]any)) != 2 {
				t.Fatal("lost duplicate catalog entries", m)
			}
		} else if m["catalog_entries"] != nil {
			t.Fatal("associated a different group or type", m)
		}
	}
	// A prefix match on the object name must not associate it either.
	o := objects[1]
	o.RawName = bytes.Clone(o.RawName)
	o.RawName[6] = 0xc1
	views = objectViews([]Object{catalog, o})
	_, m, err := views[o.Offset].Metadata()
	if err != nil || m["catalog_entries"] != nil {
		t.Fatal("associated a name prefix", m, err)
	}
}

func TestCatalogMetadata(t *testing.T) {
	b := catalogFixture(t, 2)
	m, dir, err := catalogMetadata(&starfile.Bytes{Data: b})
	if err != nil || dir == nil || m["library"] != "QGPL" || m["entry_count"] != int64(2) || m["entries_decoded"] != true {
		t.Fatal(m, dir, err)
	}
	entries, err := dir.View.Entries()
	if err != nil || len(entries) != 2 || entries[0].Name == entries[1].Name {
		t.Fatal(entries, err)
	}
	if entries[0].Attributes["associated_name"] != "QPGMR" || entries[0].Attributes["external_type"] != "*CLS" {
		t.Fatal(entries[0])
	}
	// The raw record must be a borrowed slice, not a reconstructed record that
	// omits the unknown fields.
	b[catalogPrefixSize+150] = 0x55
	raw, err := starfile.ReadAll(entries[0].Reader.(starfile.File))
	if err != nil || len(raw) != catalogEntrySize || raw[150] != 0x55 {
		t.Fatal(raw, err)
	}
}

func TestCatalogBoundsAndGeneration(t *testing.T) {
	for _, tc := range []struct {
		name string
		make func() []byte
	}{
		{"short", func() []byte { return make([]byte, 12) }},
		{"different prefix", func() []byte { b := catalogFixture(t, 1); b[0] = 0; return b }},
		{"wrong library type", func() []byte { b := catalogFixture(t, 1); b[32] = 0; return b }},
		{"missing record", func() []byte { b := catalogFixture(t, 1); return b[:len(b)-1] }},
		{"overflow count", func() []byte { b := catalogFixture(t, 1); binary.BigEndian.PutUint32(b[42:], ^uint32(0)); return b }},
		{"inspection limit", func() []byte { return catalogFixture(t, catalogEntryLimit+1) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, dir, err := catalogMetadata(&starfile.Bytes{Data: tc.make()})
			if err != nil || dir != nil || (m["recognized"] != false && m["entries_decoded"] != false) {
				t.Fatal(m, dir, err)
			}
		})
	}
}

func TestCatalogDescription(t *testing.T) {
	b := catalogFixture(t, 1)
	offset := len(b)
	b = append(b, make([]byte, 4+50)...)
	binary.BigEndian.PutUint32(b[offset:], 50)
	putText(t, b[offset+4:], "Synthetic catalog description")
	binary.BigEndian.PutUint32(b[catalogPrefixSize+75:], uint32(offset))
	_, dir, err := catalogMetadata(&starfile.Bytes{Data: b})
	if err != nil || dir == nil {
		t.Fatal(dir, err)
	}
	entries, err := dir.View.Entries()
	if err != nil {
		t.Fatal(err)
	}
	d := entries[0].Attributes["description"].(map[string]any)
	if d["decoded"] != true || d["length"] != int64(50) || strings.TrimRight(d["text"].(string), " ") != "Synthetic catalog description" {
		t.Fatal(d)
	}
	for _, off := range []int64{0, int64(len(b)), int64(len(b) - 2), 1 << 32} {
		d, err := catalogDescription(&starfile.Bytes{Data: b}, off, int64(offset))
		if err != nil || d["decoded"] != false {
			t.Fatal(off, d, err)
		}
	}
	binary.BigEndian.PutUint32(b[offset:], 51)
	d, err = catalogDescription(&starfile.Bytes{Data: b}, int64(offset), int64(offset))
	if err != nil || d["decoded"] != false {
		t.Fatal(d, err)
	}
}
