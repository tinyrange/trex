package native

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"testing"
)

// A single-folder MSZIP CAB. Every child shares folder index zero,
// including the nested cabinets: a cache keyed only by folder index would
// corrupt this fixture rather than merely affecting its read count.
func compositionTestCAB(t *testing.T, names []string, contents [][]byte) []byte {
	header := make([]byte, 44)
	copy(header, "MSCF")
	header[24], header[25] = 3, 1
	binary.LittleEndian.PutUint32(header[16:], 44)
	binary.LittleEndian.PutUint16(header[26:], 1)
	binary.LittleEndian.PutUint16(header[28:], uint16(len(names)))
	binary.LittleEndian.PutUint16(header[40:], 1)
	data := header
	var payload []byte
	for i, name := range names {
		record := make([]byte, 16)
		binary.LittleEndian.PutUint32(record, uint32(len(contents[i])))
		binary.LittleEndian.PutUint32(record[4:], uint32(len(payload)))
		data = append(data, record...)
		data = append(data, []byte(name)...)
		data = append(data, 0)
		payload = append(payload, contents[i]...)
	}
	binary.LittleEndian.PutUint32(data[36:], uint32(len(data)))
	binary.LittleEndian.PutUint16(data[42:], 1) // MSZIP exercises the shared decoded cache.
	var encoded bytes.Buffer
	encoded.WriteString("CK")
	w, err := flate.NewWriter(&encoded, flate.BestSpeed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	block := make([]byte, 8)
	binary.LittleEndian.PutUint16(block[4:], uint16(encoded.Len()))
	binary.LittleEndian.PutUint16(block[6:], uint16(len(payload)))
	data = append(data, block...)
	data = append(data, encoded.Bytes()...)
	binary.LittleEndian.PutUint32(data[8:], uint32(len(data)))
	return data
}

func TestCompositionCatalogSharesBoundedFolderCache(t *testing.T) {
	doc := func(name string) []byte {
		return []byte(fmt.Sprintf(`<CompDB Name="%s" BuildArch="amd64"><Features/><Packages/></CompDB>`, name))
	}
	first := compositionTestCAB(t, []string{"first.xml"}, [][]byte{doc("first")})
	second := compositionTestCAB(t, []string{"second.xml"}, [][]byte{doc("second")})
	nested := compositionTestCAB(t, []string{"second.compdb.xml.cab", "third.compdb.xml"}, [][]byte{second, doc("third")})
	source := compositionTestCAB(t, []string{"first.compdb.xml.cab", "outer.aggregatedmetadata_nested.cab", "fourth.compdb.xml"}, [][]byte{first, nested, doc("fourth")})
	cabinets := newCompositionCabinets()
	archive, err := cabinets.open(&starfile.Bytes{Name: "catalog", Data: source})
	if err != nil {
		t.Fatal(err)
	}
	databases, err := compositionDatabases(archive, cabinets)
	if err != nil {
		t.Fatal(err)
	}
	if len(databases) != 4 {
		t.Fatalf("got %d documents", len(databases))
	}
	for i, name := range []string{"first", "second", "third", "fourth"} {
		if databases[i].Name != name {
			t.Fatalf("document %d: %+v", i, databases[i])
		}
	}
	stats := cabinets.cache.Stats()
	if stats.Loads != 4 || stats.Hits == 0 || stats.Bytes > maximumCompositionCache {
		t.Fatalf("solid folders should decode once per distinct archive: %+v", stats)
	}
	// A subsequent catalog never aliases this cache, even with identical paths.
	other := newCompositionCabinets()
	otherSource := compositionTestCAB(t, []string{"fourth.compdb.xml"}, [][]byte{doc("changed")})
	otherArchive, err := other.open(&starfile.Bytes{Name: "catalog", Data: otherSource})
	if err != nil {
		t.Fatal(err)
	}
	otherDBs, err := compositionDatabases(otherArchive, other)
	if err != nil || len(otherDBs) != 1 || otherDBs[0].Name != "changed" {
		t.Fatalf("independent catalog: %v %v", otherDBs, err)
	}
}
