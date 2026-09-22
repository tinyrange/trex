package ese

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

func TestRevision2LinearTaggedValues(t *testing.T) {
	d := &Database{info: Info{Version: 0x620, Revision: 2, PageSize: 8192}}
	// An unflagged scalar followed by a flagged binary value and an empty value.
	data := []byte{0, 1, 3, 0, 'a', 'b', 'c', 1, 1, 3, 0x80, 1, 0xfe, 0xff, 2, 1, 0, 0}
	values, err := d.decodeTaggedValues(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(values) != 3 || string(values[256].data) != "abc" || values[257].flags != 1 || !bytes.Equal(values[257].data, []byte{0xfe, 0xff}) || len(values[258].data) != 0 {
		t.Fatalf("decoded values: %#v", values)
	}
	for _, malformed := range [][]byte{
		{0}, {0, 1, 4, 0, 0}, {0, 1, 0, 0x80}, {0, 0, 0, 0},
	} {
		if _, err := d.decodeTaggedValues(malformed); err == nil {
			t.Fatalf("accepted malformed tuple %x", malformed)
		}
	}
}

func TestBuildRevision2Database(t *testing.T) {
	file, err := Build([]TableDefinition{{
		Name: "objects",
		Columns: []ColumnDefinition{
			{Name: "id", Identifier: 1, Type: ColumnSignedLong, Flags: 4},
			{Name: "name", Identifier: 256, Type: ColumnLongText, CodePage: 1200},
			{Name: "classes", Identifier: 257, Type: ColumnSignedLong},
			{Name: "description", Identifier: 258, Type: ColumnLongText, CodePage: 1200},
		},
		Indexes: []IndexDefinition{{Name: "id", Columns: []int32{1}, Flags: 0x1002f}},
		Rows:    []Row{{"id": int32(1), "name": "Domain", "classes": []any{int32(65540), int32(65536)}, "description": []any{strings.Repeat("directory", 1200), strings.Repeat("schema", 900)}}},
	}}, BuildOptions{PageSize: 8192, Revision: 2})
	if err != nil {
		t.Fatal(err)
	}
	db, err := Open(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Verify(4096); err != nil {
		t.Fatal(err)
	}
	rows, err := db.Rows("objects", 10)
	if err != nil {
		t.Fatal(err)
	}
	want := []Record{{{Name: "id", Value: int32(1)}, {Name: "name", Value: "Domain"}, {Name: "classes", Value: []any{int32(65540), int32(65536)}}, {Name: "description", Value: []any{strings.Repeat("directory", 1200), strings.Repeat("schema", 900)}}}}
	if !reflect.DeepEqual(rows, want) {
		t.Fatalf("rows = %#v", rows)
	}
	if len(db.Tables()) != 3 || len(db.Tables()[0].Columns) != 17 {
		t.Fatalf("wrong generation of catalog: %#v", db.Tables())
	}
}

func TestRevision2RepeatedAttributes(t *testing.T) {
	d := &Database{info: Info{Version: 0x620, Revision: 2, PageSize: 8192}}
	table := &Table{Columns: []Column{{Name: "objectClass", Identifier: 771, typeCode: 4}}}
	// A real revision-2 objectClass shape: consecutive tuples for one column.
	record := []byte{0, 127, 4, 0, 3, 3, 4, 0, 4, 0, 1, 0, 3, 3, 4, 0, 0, 0, 1, 0}
	got, err := d.decodeRecord(table, record)
	if err != nil {
		t.Fatal(err)
	}
	values, ok := got[0].Value.([]any)
	if !ok || len(values) != 2 || values[0] != int32(65540) || values[1] != int32(65536) {
		t.Fatalf("objectClass: %#v", got)
	}
}
