package ibmisave

import (
	"encoding/binary"
	starfile "github.com/tinyrange/trex/storage/star"
	"testing"
)

func TestQSYSCatalog044aCommonRecords(t *testing.T) {
	b := catalogFixture(t, 2)
	be := binary.BigEndian
	be.PutUint16(b, 0x044a)
	putText(t, b[2:32], "QSYS")
	putText(t, b[catalogPrefixSize:catalogPrefixSize+30], "QSYS")
	be.PutUint16(b[catalogPrefixSize+30:], 0x0401)
	putText(t, b[catalogPrefixSize+catalogEntrySize:catalogPrefixSize+catalogEntrySize+30], "MYPROGRAM")
	be.PutUint16(b[catalogPrefixSize+catalogEntrySize+30:], 0x0201)
	// The observed QSYS descriptions begin beyond the complete common-record table.
	off := len(b) + 2
	b = append(b, make([]byte, 56)...)
	be.PutUint32(b[off:], 50)
	putText(t, b[off+4:off+54], "QSYS synthetic description")
	be.PutUint32(b[catalogPrefixSize+75:], uint32(off))
	m, v, err := catalogMetadata(&starfile.Bytes{Data: b})
	if err != nil || v == nil || m["layout_prefix_hex"] != "044a" || m["library"] != "QSYS" {
		t.Fatal(m, err)
	}
	entries, err := v.View.Entries()
	if err != nil || len(entries) != 2 {
		t.Fatal(entries, err)
	}
	if entries[0].Attributes["internal_type_hex"] != "0401" || entries[1].Attributes["name"] != "MYPROGRAM" || entries[1].Attributes["internal_type_hex"] != "0201" {
		t.Fatal(entries)
	}
	if entries[0].Attributes["description"].(map[string]any)["decoded"] != true {
		t.Fatal(entries[0])
	}
	// A wrong stride must not be inferred from the generation tag.
	be.PutUint32(b[42:], uint32(len(b)))
	m, v, err = catalogMetadata(&starfile.Bytes{Data: b})
	if err != nil || v != nil || m["entries_decoded"] != false {
		t.Fatal(m, v, err)
	}
}
func FuzzCatalogProfiles(f *testing.F) {
	seed := make([]byte, 112)
	binary.BigEndian.PutUint16(seed, 0x044a)
	binary.BigEndian.PutUint16(seed[32:], 0x0401)
	f.Add(seed)
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			return
		}
		_, v, err := catalogMetadata(&starfile.Bytes{Data: b})
		if err == nil && v != nil {
			entries, e := v.View.Entries()
			if e != nil || len(entries) > catalogEntryLimit {
				t.Fatal(e)
			}
		}
	})
}
