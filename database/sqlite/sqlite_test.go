package sqlite

import (
	"encoding/binary"
	"io"
	"math"
	"reflect"
	"strings"
	"testing"
)

type memoryReader []byte

func (r memoryReader) Size() int64 { return int64(len(r)) }
func (r memoryReader) ReadAt(data []byte, offset int64) (int, error) {
	if offset < 0 || offset >= int64(len(r)) {
		return 0, io.EOF
	}
	count := copy(data, r[offset:])
	if count != len(data) {
		return count, io.EOF
	}
	return count, nil
}

func TestOpenReadsSchemaAndRecords(t *testing.T) {
	databaseBytes := testDatabase([][]any{
		{int64(-129), float64(1.25), "hello", []byte{0, 1, 2}, nil},
		{int64(1), float64(-2.5), "world", []byte{}, "last"},
	})
	database, err := Open(memoryReader(databaseBytes), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := database.Info(), (Info{PageSize: 512, PageCount: 2, Encoding: 1, UserVersion: 17, ApplicationID: 0x54524558}); got != want {
		t.Fatalf("Info() = %#v, want %#v", got, want)
	}
	if got, want := database.Schema(), []SchemaEntry{{Type: "table", Name: "items", TableName: "items", RootPage: 2, SQL: "CREATE TABLE items(integer_value,real_value,text_value,blob_value,null_value)"}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Schema() = %#v, want %#v", got, want)
	}
	rows, err := database.Rows("ITEMS", 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].RowID == nil || *rows[0].RowID != 1 || rows[1].RowID == nil || *rows[1].RowID != 2 {
		t.Fatalf("unexpected row IDs: %#v", rows)
	}
	if got, want := rows[0].Values, []any{int64(-129), float64(1.25), "hello", []byte{0, 1, 2}, nil}; !reflect.DeepEqual(got, want) {
		t.Fatalf("first row = %#v, want %#v", got, want)
	}
}

func TestOpenAppliesLastCommittedWAL(t *testing.T) {
	base := testDatabase([][]any{{int64(1), float64(1), "before", []byte(nil), nil}})
	updated := testDatabase([][]any{{int64(2), float64(2), "after", []byte{9}, nil}})
	wal := testWAL(updated[512:1024], false)
	database, err := Open(memoryReader(base), memoryReader(wal))
	if err != nil {
		t.Fatal(err)
	}
	rows, err := database.Rows("items", 10)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := rows[0].Values[2], any("after"); got != want {
		t.Fatalf("WAL row text = %#v, want %#v", got, want)
	}
	if database.Info().WALFrames != 1 {
		t.Fatalf("WALFrames = %d, want 1", database.Info().WALFrames)
	}

	wal[len(wal)-1] ^= 1
	database, err = Open(memoryReader(base), memoryReader(wal))
	if err != nil {
		t.Fatal(err)
	}
	rows, err = database.Rows("items", 10)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := rows[0].Values[2], any("before"); got != want {
		t.Fatalf("torn WAL should be ignored: got %#v, want %#v", got, want)
	}
}

func TestOpenReadsOverflowPayload(t *testing.T) {
	text := make([]byte, 650)
	for index := range text {
		text[index] = byte('a' + index%26)
	}
	record := testRecord([]any{string(text)})
	databaseBytes := testHeader(3)
	testLeafPage(databaseBytes[:512], 100, 0x0d, [][]byte{testTableCell(1, testRecord([]any{"table", "large", "large", int64(2), "CREATE TABLE large(value)"}))})

	usable := 512
	maximumLocal := usable - 35
	minimumLocal := ((usable - 12) * 32 / 255) - 23
	local := minimumLocal + (len(record)-minimumLocal)%(usable-4)
	if local > maximumLocal {
		local = minimumLocal
	}
	cell := append(testVarint(uint64(len(record))), testVarint(1)...)
	cell = append(cell, record[:local]...)
	overflowPointer := make([]byte, 4)
	binary.BigEndian.PutUint32(overflowPointer, 3)
	cell = append(cell, overflowPointer...)
	testLeafPage(databaseBytes[512:1024], 0, 0x0d, [][]byte{cell})
	copy(databaseBytes[1028:], record[local:])

	database, err := Open(memoryReader(databaseBytes), nil)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := database.Rows("large", 10)
	if err != nil {
		t.Fatal(err)
	}
	if got := rows[0].Values[0]; got != string(text) {
		t.Fatalf("overflow text length/value mismatch: got %d bytes", len(got.(string)))
	}
}

func TestIndexInteriorRecordsRemainInOrder(t *testing.T) {
	databaseBytes := testHeader(4)
	schema := testRecord([]any{"index", "item_index", "items", int64(2), "CREATE INDEX item_index ON items(value)"})
	testLeafPage(databaseBytes[:512], 100, 0x0d, [][]byte{testTableCell(1, schema)})
	testLeafPage(databaseBytes[1024:1536], 0, 0x0a, [][]byte{testIndexCell(testRecord([]any{"alpha", int64(1)}))})
	testLeafPage(databaseBytes[1536:2048], 0, 0x0a, [][]byte{testIndexCell(testRecord([]any{"zulu", int64(3)}))})

	page := databaseBytes[512:1024]
	page[0] = 0x02
	binary.BigEndian.PutUint16(page[3:5], 1)
	binary.BigEndian.PutUint32(page[8:12], 4)
	middleRecord := testRecord([]any{"middle", int64(2)})
	cell := make([]byte, 4)
	binary.BigEndian.PutUint32(cell, 3)
	cell = append(cell, testIndexCell(middleRecord)...)
	offset := len(page) - len(cell)
	copy(page[offset:], cell)
	binary.BigEndian.PutUint16(page[5:7], uint16(offset))
	binary.BigEndian.PutUint16(page[12:14], uint16(offset))

	database, err := Open(memoryReader(databaseBytes), nil)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := database.Rows("item_index", 10)
	if err != nil {
		t.Fatal(err)
	}
	values := make([]string, 0, len(rows))
	for _, row := range rows {
		values = append(values, row.Values[0].(string))
	}
	if want := []string{"alpha", "middle", "zulu"}; !reflect.DeepEqual(values, want) {
		t.Fatalf("index values = %v, want %v", values, want)
	}
}

func TestBuildRoundTripWithoutSQLiteDependency(t *testing.T) {
	longText := make([]byte, 1800)
	for index := range longText {
		longText[index] = byte('a' + index%26)
	}
	row1, row2, row3 := int64(1), int64(2), int64(3)
	file, err := Build([]Object{
		{
			Type: "table", Name: "items", TableName: "items",
			SQL: "CREATE TABLE items(id INTEGER PRIMARY KEY NOT NULL,name TEXT,payload BLOB)",
			Rows: []Row{
				{RowID: &row1, Values: []any{nil, "alpha", []byte{1}}},
				{RowID: &row2, Values: []any{nil, string(longText), []byte{2, 3}}},
				{RowID: &row3, Values: []any{nil, "zulu", nil}},
			},
		},
		{
			Type: "index", Name: "items_name", TableName: "items",
			SQL: "CREATE INDEX items_name ON items(name)",
			Rows: []Row{
				{Values: []any{"alpha", int64(1)}},
				{Values: []any{string(longText), int64(2)}},
				{Values: []any{"zulu", int64(3)}},
			},
		},
		{Type: "trigger", Name: "items_trigger", TableName: "items", SQL: "CREATE TRIGGER items_trigger AFTER DELETE ON items BEGIN SELECT 1; END"},
	}, BuildOptions{PageSize: 1024, Encoding: 1, UserVersion: 2560})
	if err != nil {
		t.Fatal(err)
	}
	database, err := Open(file, nil)
	if err != nil {
		t.Fatal(err)
	}
	if database.Info().UserVersion != 2560 || database.Info().PageSize != 1024 {
		t.Fatalf("unexpected built database info: %#v", database.Info())
	}
	rows, err := database.Rows("items", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 || rows[1].Values[1] != string(longText) {
		t.Fatalf("built table rows did not round trip: %#v", rows)
	}
	indexRows, err := database.Rows("items_name", 10)
	if err != nil {
		t.Fatal(err)
	}
	if got := []any{indexRows[0].Values[0], indexRows[1].Values[0], indexRows[2].Values[0]}; !reflect.DeepEqual(got, []any{"alpha", string(longText), "zulu"}) {
		t.Fatalf("built index rows = %#v", got)
	}
}

func TestBuildTableFanoutDoesNotCreateUnaryInteriorPage(t *testing.T) {
	for _, count := range []int{21, 41, 401} {
		rows := make([]Row, count)
		for index := range rows {
			rowID := int64(index + 1)
			rows[index] = Row{RowID: &rowID, Values: []any{nil, int64(index)}}
		}
		file, err := Build([]Object{{
			Type: "table", Name: "items", TableName: "items",
			SQL:  "CREATE TABLE items(id INTEGER PRIMARY KEY NOT NULL,value INTEGER)",
			Rows: rows,
		}}, BuildOptions{PageSize: 1024, Encoding: 1})
		if err != nil {
			t.Fatalf("Build(%d rows): %v", count, err)
		}
		database, err := Open(file, nil)
		if err != nil {
			t.Fatalf("Open(%d rows): %v", count, err)
		}
		got, err := database.Rows("items", count+1)
		if err != nil {
			t.Fatalf("Rows(%d rows): %v", count, err)
		}
		if len(got) != count || got[count-1].Values[1] != int64(count-1) {
			t.Fatalf("round trip count %d returned %#v", count, got)
		}
	}
}

func TestBuildIndexDoesNotCreateEmptyChildPages(t *testing.T) {
	rows := make([]Row, 300)
	for index := range rows {
		rows[index] = Row{Values: []any{int64(index), strings.Repeat("x", 80), int64(index + 1)}}
	}
	file, err := Build([]Object{
		{Type: "table", Name: "items", TableName: "items", SQL: "CREATE TABLE items(id INTEGER PRIMARY KEY,value INTEGER)"},
		{Type: "index", Name: "items_value", TableName: "items", SQL: "CREATE INDEX items_value ON items(value)", Rows: rows},
	}, BuildOptions{PageSize: 1024, Encoding: 1})
	if err != nil {
		t.Fatal(err)
	}
	// Objects are allocated in schema order, so the index root is page 3.
	visited := map[uint32]bool{}
	var visit func(uint32, bool)
	visit = func(number uint32, root bool) {
		if number == 0 || int(number)*1024 > len(file.Data) {
			t.Fatalf("invalid child page %d", number)
		}
		if visited[number] {
			t.Fatalf("index page %d is referenced more than once", number)
		}
		visited[number] = true
		page := file.Data[(number-1)*1024 : number*1024]
		count := int(binary.BigEndian.Uint16(page[3:5]))
		switch page[0] {
		case 0x0a:
			if !root && count == 0 {
				t.Fatalf("non-root index leaf page %d is empty", number)
			}
		case 0x02:
			if !root && count < 2 {
				t.Fatalf("non-root index interior page %d has only %d cell(s)", number, count)
			}
			if root && count == 0 {
				t.Fatalf("root index interior page %d has no cells", number)
			}
			for index := 0; index < count; index++ {
				offset := int(binary.BigEndian.Uint16(page[12+index*2 : 14+index*2]))
				visit(binary.BigEndian.Uint32(page[offset:offset+4]), false)
			}
			visit(binary.BigEndian.Uint32(page[8:12]), false)
		default:
			t.Fatalf("index page %d has type %#x", number, page[0])
		}
	}
	visit(3, true)
	database, err := Open(file, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := database.Rows("items_value", len(rows)+1)
	if err != nil || len(got) != len(rows) {
		t.Fatalf("index round trip returned %d rows: %v", len(got), err)
	}
}

func testDatabase(rows [][]any) []byte {
	database := testHeader(2)
	schema := testRecord([]any{"table", "items", "items", int64(2), "CREATE TABLE items(integer_value,real_value,text_value,blob_value,null_value)"})
	testLeafPage(database[:512], 100, 0x0d, [][]byte{testTableCell(1, schema)})
	cells := make([][]byte, 0, len(rows))
	for index, row := range rows {
		cells = append(cells, testTableCell(int64(index+1), testRecord(row)))
	}
	testLeafPage(database[512:1024], 0, 0x0d, cells)
	return database
}

func testHeader(pageCount uint32) []byte {
	database := make([]byte, int(pageCount)*512)
	copy(database[:16], databaseMagic)
	binary.BigEndian.PutUint16(database[16:18], 512)
	database[18], database[19], database[20] = 1, 1, 0
	database[21], database[22], database[23] = 64, 32, 32
	binary.BigEndian.PutUint32(database[24:28], 1)
	binary.BigEndian.PutUint32(database[28:32], pageCount)
	binary.BigEndian.PutUint32(database[44:48], 4)
	binary.BigEndian.PutUint32(database[56:60], 1)
	binary.BigEndian.PutUint32(database[60:64], 17)
	binary.BigEndian.PutUint32(database[68:72], 0x54524558)
	binary.BigEndian.PutUint32(database[92:96], 1)
	binary.BigEndian.PutUint32(database[96:100], 3046000)
	return database
}

func testLeafPage(page []byte, headerOffset int, pageType byte, cells [][]byte) {
	page[headerOffset] = pageType
	binary.BigEndian.PutUint16(page[headerOffset+3:headerOffset+5], uint16(len(cells)))
	content := len(page)
	for index, cell := range cells {
		content -= len(cell)
		copy(page[content:], cell)
		binary.BigEndian.PutUint16(page[headerOffset+8+index*2:headerOffset+10+index*2], uint16(content))
	}
	binary.BigEndian.PutUint16(page[headerOffset+5:headerOffset+7], uint16(content))
}

func testTableCell(rowID int64, record []byte) []byte {
	cell := append([]byte{}, testVarint(uint64(len(record)))...)
	cell = append(cell, testVarint(uint64(rowID))...)
	return append(cell, record...)
}

func testIndexCell(record []byte) []byte {
	return append(testVarint(uint64(len(record))), record...)
}

func testRecord(values []any) []byte {
	serials := make([]byte, 0, len(values))
	body := make([]byte, 0)
	for _, value := range values {
		var serial uint64
		var field []byte
		switch value := value.(type) {
		case nil:
			serial = 0
		case int64:
			serial = 6
			field = make([]byte, 8)
			binary.BigEndian.PutUint64(field, uint64(value))
		case float64:
			serial = 7
			field = make([]byte, 8)
			binary.BigEndian.PutUint64(field, math.Float64bits(value))
		case string:
			field = []byte(value)
			serial = 13 + uint64(len(field))*2
		case []byte:
			field = value
			serial = 12 + uint64(len(field))*2
		default:
			panic("unsupported test record value")
		}
		serials = append(serials, testVarint(serial)...)
		body = append(body, field...)
	}
	headerSize := len(serials) + 1
	for len(testVarint(uint64(headerSize)))+len(serials) != headerSize {
		headerSize = len(testVarint(uint64(headerSize))) + len(serials)
	}
	record := append(testVarint(uint64(headerSize)), serials...)
	return append(record, body...)
}

func testVarint(value uint64) []byte {
	for size := 1; size <= 8; size++ {
		if value < uint64(1)<<(7*size) {
			output := make([]byte, size)
			for index := size - 1; index >= 0; index-- {
				output[index] = byte(value & 0x7f)
				if index != size-1 {
					output[index] |= 0x80
				}
				value >>= 7
			}
			return output
		}
	}
	output := make([]byte, 9)
	output[8] = byte(value)
	value >>= 8
	for index := 7; index >= 0; index-- {
		output[index] = byte(value&0x7f) | 0x80
		value >>= 7
	}
	return output
}

func testWAL(page []byte, bigEndianChecksums bool) []byte {
	wal := make([]byte, 32+24+len(page))
	order := binary.ByteOrder(binary.LittleEndian)
	magic := uint32(0x377f0682)
	if bigEndianChecksums {
		order = binary.BigEndian
		magic = 0x377f0683
	}
	binary.BigEndian.PutUint32(wal[:4], magic)
	binary.BigEndian.PutUint32(wal[4:8], 3007000)
	binary.BigEndian.PutUint32(wal[8:12], uint32(len(page)))
	binary.BigEndian.PutUint32(wal[16:20], 0x12345678)
	binary.BigEndian.PutUint32(wal[20:24], 0x9abcdef0)
	s0, s1 := walChecksum(wal[:24], order, 0, 0)
	binary.BigEndian.PutUint32(wal[24:28], s0)
	binary.BigEndian.PutUint32(wal[28:32], s1)
	frame := wal[32:]
	binary.BigEndian.PutUint32(frame[:4], 2)
	binary.BigEndian.PutUint32(frame[4:8], 2)
	copy(frame[8:16], wal[16:24])
	copy(frame[24:], page)
	s0, s1 = walChecksum(frame[:8], order, s0, s1)
	s0, s1 = walChecksum(frame[24:], order, s0, s1)
	binary.BigEndian.PutUint32(frame[16:20], s0)
	binary.BigEndian.PutUint32(frame[20:24], s1)
	return wal
}
