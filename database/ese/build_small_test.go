package ese

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"reflect"
	"testing"
)

func TestBuildModernSmallCatalog(t *testing.T) {
	rows := make([]Row, 1200)
	for i := range rows {
		key := make([]byte, 32)
		binary.BigEndian.PutUint32(key, uint32(i))
		rows[i] = Row{"Hash": key, "Catalogs": []byte(fmt.Sprintf("catalog-%04d.cat|", i))}
	}
	tables := []TableDefinition{{Name: "Hashes", Columns: []ColumnDefinition{
		{Name: "Hash", Identifier: 1, Type: ColumnBinary, Maximum: 32, Flags: 1},
		{Name: "Catalogs", Identifier: 256, Type: ColumnLongBinary},
	}, Indexes: []IndexDefinition{{Name: "HashIndex", Columns: []int32{1}, Flags: 0x1002f, KeyMost: 33}}, Rows: rows}}
	options := BuildOptions{PageSize: 4096, Revision: 20}
	file, err := Build(tables, options)
	if err != nil {
		t.Fatal(err)
	}
	db, err := Open(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Verify(10000); err != nil {
		t.Fatal(err)
	}
	got, err := db.Rows("Hashes", 2000)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(rows) {
		t.Fatalf("row count %d", len(got))
	}
	for i, row := range got {
		want := Record{{Name: "Hash", Value: rows[i]["Hash"]}, {Name: "Catalogs", Value: rows[i]["Catalogs"]}}
		if !reflect.DeepEqual(row, want) {
			t.Fatalf("row %d: %#v", i, row)
		}
	}
	entries, err := db.IndexEntries("Hashes", "HashIndex", 2000)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(rows) {
		t.Fatalf("index count %d", len(entries))
	}
	for i, entry := range entries {
		if !bytes.Equal(entry.Key, append([]byte{0x7f}, rows[i]["Hash"].([]byte)...)) {
			t.Fatalf("index key %d: %x", i, entry.Key)
		}
	}
	header := make([]byte, 4096)
	if _, err := file.ReadAt(header, 0); err != nil {
		t.Fatal(err)
	}
	if binary.LittleEndian.Uint32(header[667:671]) != 1 {
		t.Fatal("not JET_filetypeDatabase")
	}
	again, err := Build(tables, options)
	if err != nil {
		t.Fatal(err)
	}
	other := make([]byte, 4096)
	if _, err := again.ReadAt(other, 0); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(header, other) {
		t.Fatal("non-reproducible header")
	}
	tables[0].Rows = nil
	different, err := Build(tables, options)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := different.ReadAt(other, 0); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(header[24:52], other[24:52]) {
		t.Fatal("different databases have identical attachment signatures")
	}
	catalog, err := db.Rows("MSysObjects", 1000)
	if err != nil {
		t.Fatal(err)
	}
	foundDefault := false
	for _, r := range catalog {
		fields := map[string]any{}
		for _, f := range r {
			fields[f.Name] = f.Value
		}
		if fields["Type"] == int16(1) {
			density, ok := fields["SpaceUsage"].(int32)
			if !ok || density < 20 || density > 100 {
				t.Fatalf("invalid native table density: %v", fields)
			}
		}
		if fields["Name"] == "iValue" {
			if !reflect.DeepEqual(fields["DefaultValue"], []byte{0, 0, 0, 0}) {
				t.Fatalf("escrow column missing native default: %v", fields)
			}
			foundDefault = true
		}
	}
	if !foundDefault {
		t.Fatal("MSysLocales escrow column absent")
	}
	raw := make([]byte, 4096)
	if _, err := file.ReadAt(raw, 5*4096); err != nil {
		t.Fatal(err)
	}
	raw[100] ^= 1
	if err := verifyPageChecksum(raw, 4); err == nil {
		t.Fatal("corrupt modern small page accepted")
	}
}

func TestFixedBinaryOffsetsAndNulls(t *testing.T) {
	columns := []ColumnDefinition{{Name: "Binary", Identifier: 1, Type: ColumnBinary, Maximum: 20}, {Name: "After", Identifier: 2, Type: ColumnSignedLong, Maximum: 4}}
	for _, value := range []any{nil, []byte{0xab, 0xcd}} {
		record, err := encodeRecordPage(columns, Row{"Binary": value, "After": int32(1234)}, true)
		if err != nil {
			t.Fatal(err)
		}
		if binary.LittleEndian.Uint32(record[24:28]) != 1234 {
			t.Fatalf("wrong fixed offset: %x", record)
		}
		if value == nil && record[28]&1 == 0 {
			t.Fatal("NULL bitmap missing")
		}
		if value != nil && (!bytes.Equal(record[4:6], []byte{0xab, 0xcd}) || !bytes.Equal(record[6:24], make([]byte, 18))) {
			t.Fatal("fixed binary not padded")
		}
	}
	key, err := encodeIndexColumns(columns, Row{"Binary": []byte{0xab, 0xcd}}, []int32{1})
	if err != nil {
		t.Fatal(err)
	}
	want := append([]byte{0x7f, 0xab, 0xcd}, make([]byte, 18)...)
	if !bytes.Equal(key, want) {
		t.Fatalf("unpadded fixed binary index: %x", key)
	}
	if _, err := encodeRecordPage(columns, Row{"Binary": make([]byte, 21)}, true); err == nil {
		t.Fatal("oversize fixed binary accepted")
	}
}
