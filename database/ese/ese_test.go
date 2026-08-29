package ese

import (
	"bytes"
	"encoding/binary"
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
	row := make([]byte, 8)
	row[0], row[1] = 1, 127
	binary.LittleEndian.PutUint16(row[2:4], 8)
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
	const fixedEnd = 33
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
