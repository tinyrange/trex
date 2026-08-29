package ese

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"strings"
	"testing"
)

type testReader struct{ *bytes.Reader }

func (r testReader) Size() int64 { return r.Reader.Size() }

func TestOpenRejectsNonESEInput(t *testing.T) {
	data := make([]byte, 4096)
	_, err := Open(testReader{bytes.NewReader(data)})
	if err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("Open error = %v, want invalid magic", err)
	}
}

func TestStarlarkValuePreservesBinaryAndNestedValues(t *testing.T) {
	value, err := eseStarlarkValue([]any{uint32(7), []byte{0, 1}, "name"})
	if err != nil {
		t.Fatal(err)
	}
	if got := value.String(); got != `[7, b"\x00\x01", "name"]` {
		t.Fatalf("value = %s", got)
	}
}

func TestNewChecksumDetectsCorruption(t *testing.T) {
	page := make([]byte, 32768)
	binary.LittleEndian.PutUint64(page[8:16], 7)
	binary.LittleEndian.PutUint32(page[24:28], 2)
	binary.LittleEndian.PutUint32(page[36:40], pageFlagRoot|pageFlagLeaf)
	page[1234] = 0x5a
	if err := setPageChecksum(page, 19); err != nil {
		t.Fatal(err)
	}
	if err := verifyPageChecksum(page, 19); err != nil {
		t.Fatal(err)
	}
	page[1234] ^= 1
	if err := verifyPageChecksum(page, 19); err == nil {
		t.Fatal("corrupt page passed checksum verification")
	}
}

func TestEncodeRecordRoundTrip(t *testing.T) {
	columns := []ColumnDefinition{
		{Name: "Key", Identifier: 1, Type: ColumnSignedLong},
		{Name: "Missing", Identifier: 2, Type: ColumnSignedLong},
		{Name: "Enabled", Identifier: 3, Type: ColumnBoolean},
		{Name: "Name", Identifier: 128, Type: ColumnText, CodePage: 1200},
		{Name: "Payload", Identifier: 256, Type: ColumnLongBinary},
	}
	logical := Row{
		"Key": int32(-7), "Enabled": true, "Name": "TinyRange",
		"Payload": []byte{0x00, 0xff, 0x42},
	}
	record, err := encodeRecord(columns, logical)
	if err != nil {
		t.Fatal(err)
	}
	table := &Table{Columns: []Column{
		{Name: "Key", Identifier: 1, SpaceUsage: 4, Type: "long", typeCode: ColumnSignedLong},
		{Name: "Missing", Identifier: 2, SpaceUsage: 4, Type: "long", typeCode: ColumnSignedLong},
		{Name: "Enabled", Identifier: 3, SpaceUsage: 1, Type: "boolean", typeCode: ColumnBoolean},
		{Name: "Name", Identifier: 128, Type: "text", CodePage: 1200, typeCode: ColumnText},
		{Name: "Payload", Identifier: 256, Type: "long-binary", typeCode: ColumnLongBinary},
	}}
	database := &Database{info: Info{PageSize: 32768, Revision: 0x14}}
	decoded, err := database.decodeRecord(table, record)
	if err != nil {
		t.Fatal(err)
	}
	want := Record{
		{Name: "Key", Value: int32(-7)},
		{Name: "Enabled", Value: true},
		{Name: "Name", Value: "TinyRange"},
		{Name: "Payload", Value: []byte{0x00, 0xff, 0x42}},
	}
	if !reflect.DeepEqual(decoded, want) {
		t.Fatalf("decoded = %#v, want %#v", decoded, want)
	}
}

func TestEncodedPageRoundTrip(t *testing.T) {
	record, err := recordLeafEntry([]byte{0x7f, 0x80, 0, 0, 1}, []byte("record"))
	if err != nil {
		t.Fatal(err)
	}
	data, err := (encodedPage{
		dbtime: 17, flags: pageFlagRoot | pageFlagLeaf,
		number: 4, objid: 2, values: [][]byte{make([]byte, 16), record},
	}).encode(32768)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyPageChecksum(data, 4); err != nil {
		t.Fatal(err)
	}
	database := &Database{
		source: testReader{bytes.NewReader(append(make([]byte, 5*32768), data...))},
		info:   Info{PageSize: 32768, Revision: 0x14},
	}
	page, err := database.readPage(4)
	if err != nil {
		t.Fatal(err)
	}
	value, err := database.pageValue(page, 1)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := entryData(value)
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded) != "record" {
		t.Fatalf("record = %q", decoded)
	}
}

func TestBuildRoundTrip(t *testing.T) {
	file, err := Build([]TableDefinition{{
		Name: "Example",
		Columns: []ColumnDefinition{
			{Name: "Key", Identifier: 1, Type: ColumnSignedLong, Flags: 5, Maximum: 4},
			{Name: "Value", Identifier: 128, Type: ColumnText, CodePage: 1200, Maximum: 256},
		},
		Indexes: []IndexDefinition{{
			Name: "primary", Columns: []int32{1}, Flags: 0x10031, KeyMost: 255,
		}},
		Rows: []Row{
			{"Key": int32(2), "Value": "second"},
			{"Key": int32(1), "Value": "first"},
		},
	}}, BuildOptions{})
	if err != nil {
		t.Fatal(err)
	}
	database, err := Open(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Verify(256); err != nil {
		t.Fatal(err)
	}
	rows, err := database.Rows("Example", 10)
	if err != nil {
		t.Fatal(err)
	}
	want := []Record{
		{{Name: "Key", Value: int32(1)}, {Name: "Value", Value: "first"}},
		{{Name: "Key", Value: int32(2)}, {Name: "Value", Value: "second"}},
	}
	if !reflect.DeepEqual(rows, want) {
		t.Fatalf("rows = %#v, want %#v", rows, want)
	}
}

func TestBuildMultiPageTreeRoundTrip(t *testing.T) {
	logical := make([]Row, 5000)
	for index := range logical {
		logical[index] = Row{"Key": int32(5000 - index), "Value": strings.Repeat("x", 80)}
	}
	file, err := Build([]TableDefinition{{
		Name: "ManyRows",
		Columns: []ColumnDefinition{
			{Name: "Key", Identifier: 1, Type: ColumnSignedLong, Flags: 5, Maximum: 4},
			{Name: "Value", Identifier: 128, Type: ColumnText, CodePage: 1252, Maximum: 255},
		},
		Indexes: []IndexDefinition{{Name: "primary", Columns: []int32{1}, Flags: 0x10031}},
		Rows:    logical,
	}}, BuildOptions{})
	if err != nil {
		t.Fatal(err)
	}
	database, err := Open(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Verify(512); err != nil {
		t.Fatal(err)
	}
	rows, err := database.Rows("ManyRows", 6000)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 5000 || rows[0][0].Value != int32(1) || rows[4999][0].Value != int32(5000) {
		t.Fatalf("unexpected rows: count=%d first=%#v last=%#v", len(rows), rows[0], rows[len(rows)-1])
	}
}

func TestOpenWalksNativeCatalogAndTablePages(t *testing.T) {
	const pageSize = 4096
	image := make([]byte, 7*pageSize)
	binary.LittleEndian.PutUint32(image[4:8], 0x89abcdef)
	binary.LittleEndian.PutUint32(image[8:12], 0x620)
	binary.LittleEndian.PutUint32(image[0xe8:0xec], 0x0c)
	binary.LittleEndian.PutUint32(image[0xec:0xf0], pageSize)
	copy(image[pageSize:2*pageSize], image[:pageSize])

	tableCatalog := testCatalogRecord(2, 1, 2, 1, "Example")
	columnCatalog := testCatalogRecord(2, 2, 1, 4, "Value")
	writeTestESEPage(image[5*pageSize:6*pageSize], pageFlagRoot|pageFlagLeaf,
		[]byte{3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		append([]byte{0, 0}, tableCatalog...), append([]byte{0, 0}, columnCatalog...))
	row := make([]byte, 9)
	row[0], row[1] = 1, 127
	binary.LittleEndian.PutUint16(row[2:4], 9)
	binary.LittleEndian.PutUint32(row[4:8], 0x78563412)
	writeTestESEPage(image[2*pageSize:3*pageSize], pageFlagRoot|pageFlagLeaf,
		[]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, append([]byte{0, 0}, row...))

	database, err := Open(testReader{bytes.NewReader(image)})
	if err != nil {
		t.Fatal(err)
	}
	tables := database.Tables()
	if len(tables) != 1 || tables[0].Name != "Example" || len(tables[0].Columns) != 1 {
		t.Fatalf("tables = %#v", tables)
	}
	rows, err := database.Rows("example", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || len(rows[0]) != 1 || rows[0][0].Name != "Value" || rows[0][0].Value != int32(0x78563412) {
		t.Fatalf("rows = %#v", rows)
	}
}

func testCatalogRecord(object uint32, kind uint16, identifier, definition uint32, name string) []byte {
	const fixedEnd = 35
	record := make([]byte, fixedEnd+2+len(name))
	record[0], record[1] = 9, 128
	binary.LittleEndian.PutUint16(record[2:4], fixedEnd)
	binary.LittleEndian.PutUint32(record[4:8], object)
	binary.LittleEndian.PutUint16(record[8:10], kind)
	binary.LittleEndian.PutUint32(record[10:14], identifier)
	binary.LittleEndian.PutUint32(record[14:18], definition)
	spaceUsage := uint32(1)
	if kind == 2 {
		spaceUsage = 4
	}
	binary.LittleEndian.PutUint32(record[18:22], spaceUsage)
	binary.LittleEndian.PutUint32(record[22:26], 1)
	binary.LittleEndian.PutUint32(record[26:30], 1252)
	// The nine fixed columns are followed by two fixed-column null bytes.
	record[33], record[34] = 0, 0
	binary.LittleEndian.PutUint16(record[fixedEnd:fixedEnd+2], uint16(len(name)))
	copy(record[fixedEnd+2:], name)
	return record
}

func writeTestESEPage(page []byte, flags uint32, values ...[]byte) {
	binary.LittleEndian.PutUint32(page[36:40], flags)
	binary.LittleEndian.PutUint16(page[34:36], uint16(len(values)))
	offset := 0
	for index, value := range values {
		copy(page[40+offset:], value)
		descriptor := len(page) - 4*(index+1)
		binary.LittleEndian.PutUint16(page[descriptor:descriptor+2], uint16(len(value)))
		binary.LittleEndian.PutUint16(page[descriptor+2:descriptor+4], uint16(offset))
		offset += len(value)
	}
}
