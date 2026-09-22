package ese

import (
	"bytes"
	"testing"
)

func TestSparseMultivalueIndex(t *testing.T) {
	columns := []ColumnDefinition{{Name: "classes", Identifier: 256, Type: ColumnSignedLong}}
	index := IndexDefinition{Columns: []int32{256}, Flags: 0xcc}
	keys, err := secondaryKeys(columns, Row{"classes": []any{int32(3), int32(7), int32(3)}}, index, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 || !bytes.Equal(keys[0], []byte{0x7f, 0x80, 0, 0, 3}) || !bytes.Equal(keys[1], []byte{0x7f, 0x80, 0, 0, 7}) {
		t.Fatalf("keys=%x", keys)
	}
	keys, err = secondaryKeys(columns, Row{}, index, nil)
	if err != nil || len(keys) != 0 {
		t.Fatalf("null keys=%x err=%v", keys, err)
	}
	index.Flags |= 2
	keys, err = secondaryKeys(columns, Row{}, index, nil)
	if err != nil || len(keys) != 1 || !bytes.Equal(keys[0], []byte{0}) {
		t.Fatalf("included null=%x err=%v", keys, err)
	}
}

func TestBinaryIndexNormalization(t *testing.T) {
	// First objectGUID index key from the Windows 2000 bootstrap directory.
	guid := []byte{0, 0x29, 0x51, 0xb0, 5, 0xa2, 0x67, 0x43, 0x98, 0xd9, 0x3b, 0x80, 0xa9, 0x54, 0x9c, 0xd4}
	want := []byte{0x7f, 0, 0x29, 0x51, 0xb0, 5, 0xa2, 0x67, 0x43, 9, 0x98, 0xd9, 0x3b, 0x80, 0xa9, 0x54, 0x9c, 0xd4, 8}
	column := ColumnDefinition{Identifier: 774, Type: ColumnLongBinary}
	got, err := normalizeVariable(column, guid, false, IndexDefinition{}, nil)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("GUID key=%x err=%v", got, err)
	}
	got, err = normalizeVariable(column, []byte{1, 2, 3}, false, IndexDefinition{}, nil)
	if err != nil || !bytes.Equal(got, []byte{0x7f, 1, 2, 3, 0, 0, 0, 0, 0, 3}) {
		t.Fatalf("padded key=%x err=%v", got, err)
	}
	column.Identifier = 1
	got, err = normalizeVariable(column, []byte{1, 2, 3}, false, IndexDefinition{}, nil)
	if err != nil || !bytes.Equal(got, []byte{0x7f, 1, 2, 3}) {
		t.Fatalf("fixed key=%x err=%v", got, err)
	}
}

func TestHeapTableAndPersistedDefault(t *testing.T) {
	file, err := Build([]TableDefinition{{Name: "hidden", Columns: []ColumnDefinition{{Name: "count", Identifier: 1, Type: ColumnSignedLong, Flags: 0x30, Default: []byte{1, 0, 0, 0}}}, Rows: []Row{{"count": int32(9)}, {"count": int32(11)}}}}, BuildOptions{PageSize: 8192})
	if err != nil {
		t.Fatal(err)
	}
	db, err := Open(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Verify(256); err != nil {
		t.Fatal(err)
	}
	rows, err := db.Rows("hidden", 10)
	if err != nil || len(rows) != 2 || rows[0][0].Value != int32(9) || rows[1][0].Value != int32(11) {
		t.Fatalf("rows=%v err=%v", rows, err)
	}
	for _, table := range db.Tables() {
		if table.Name == "hidden" && len(table.Indexes) != 0 {
			t.Fatal("heap has an explicit index")
		}
	}
	catalog, err := db.Rows("MSysObjects", 100)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, row := range catalog {
		name := ""
		var value []byte
		for _, field := range row {
			if field.Name == "Name" {
				name = field.Value.(string)
			}
			if field.Name == "DefaultValue" {
				value = field.Value.([]byte)
			}
		}
		if name == "count" {
			found = bytes.Equal(value, []byte{1, 0, 0, 0})
		}
	}
	if !found {
		t.Fatal("catalog lost column default")
	}
}
