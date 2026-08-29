// Package ese reads Extensible Storage Engine (ESE/Jet Blue) databases from
// portable TinyRange storage readers.
package ese

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/tinyrange/trex/storage"
)

const (
	fileHeaderMinimum = 668
	catalogRootPage   = 4

	pageFlagRoot      = 0x00000001
	pageFlagLeaf      = 0x00000002
	pageFlagSpaceTree = 0x00000020
	pageFlagIndex     = 0x00000040
	pageFlagLongValue = 0x00000080

	tagFlagDefunct = 0x02
	tagFlagCommon  = 0x04
)

// Info describes the physical database format selected by its header.
type Info struct {
	PageSize int64
	Revision uint32
	Version  uint32
}

// Column describes one logical table column.
type Column struct {
	CodePage   uint32
	Flags      uint32
	Identifier uint32
	Name       string
	SpaceUsage int64
	Type       string

	typeCode uint32
}

// Table describes one catalog table and its columns.
type Table struct {
	FatherDataPageNumber uint32
	Name                 string
	Columns              []Column
	Indexes              []string

	longValuePage uint32
}

// Field preserves the catalog order of one record value.
type Field struct {
	Name  string
	Value any
}

// Record is one logical table record.
type Record []Field

// Database is a parsed ESE database backed by a portable random-access reader.
type Database struct {
	source storage.Reader
	info   Info
	tables []Table
	byName map[string]int
}

// Verify checks both database headers and up to maximum allocated pages. Zero
// pages in the database's reserved tail are ignored.
func (d *Database) Verify(maximum int) error {
	if maximum < 0 {
		return fmt.Errorf("ese: maximum pages must be non-negative")
	}
	for copyIndex := 0; copyIndex < 2; copyIndex++ {
		header := make([]byte, d.info.PageSize)
		if _, err := readFullAt(d.source, header, int64(copyIndex)*d.info.PageSize); err != nil {
			return fmt.Errorf("ese: header copy %d: %w", copyIndex, err)
		}
		actual, err := oldChecksum(header)
		if err != nil {
			return err
		}
		if expected := binary.LittleEndian.Uint32(header[:4]); actual != expected {
			return fmt.Errorf("ese: header copy %d checksum %#x != %#x", copyIndex, actual, expected)
		}
	}
	pages := int(d.source.Size()/d.info.PageSize) - 2
	if maximum < pages {
		pages = maximum
	}
	for index := 1; index <= pages; index++ {
		data := make([]byte, d.info.PageSize)
		if _, err := readFullAt(d.source, data, int64(index+1)*d.info.PageSize); err != nil {
			return fmt.Errorf("ese: page %d: %w", index, err)
		}
		if binary.LittleEndian.Uint64(data[8:16]) == 0 && binary.LittleEndian.Uint32(data[24:28]) == 0 && binary.LittleEndian.Uint32(data[36:40]) == 0 {
			continue
		}
		if err := verifyPageChecksum(data, uint32(index)); err != nil {
			return err
		}
	}
	return nil
}

type page struct {
	id    uint32
	data  []byte
	flags uint32
	tags  uint16
}

type pageValue struct {
	data  []byte
	flags uint8
}

type catalogRecord struct {
	objectID   uint32
	recordType uint16
	identifier uint32
	definition uint32
	spaceUsage uint32
	flags      uint32
	locale     uint32
	name       string
}

// Open validates the database header and reads its catalog. The source remains
// lazy: table pages are read only when Rows is called.
func Open(source storage.Reader) (*Database, error) {
	if source == nil {
		return nil, fmt.Errorf("ese: nil source")
	}
	header := make([]byte, fileHeaderMinimum)
	if _, err := readFullAt(source, header, 0); err != nil {
		return nil, fmt.Errorf("ese: header: %w", err)
	}
	if binary.LittleEndian.Uint32(header[4:8]) != 0x89abcdef {
		return nil, fmt.Errorf("ese: header: invalid signature")
	}
	version := binary.LittleEndian.Uint32(header[8:12])
	if version != 0x620 && version != 0x623 {
		return nil, fmt.Errorf("ese: unsupported format version %#x", version)
	}
	if fileType := binary.LittleEndian.Uint32(header[12:16]); fileType != 0 {
		return nil, fmt.Errorf("ese: unsupported file type %d", fileType)
	}
	revision := binary.LittleEndian.Uint32(header[0xe8:0xec])
	pageSize := int64(binary.LittleEndian.Uint32(header[0xec:0xf0]))
	switch pageSize {
	case 2048, 4096, 8192, 16384, 32768:
	default:
		return nil, fmt.Errorf("ese: unsupported page size %d", pageSize)
	}
	if source.Size() < pageSize*3 || source.Size()%pageSize != 0 {
		return nil, fmt.Errorf("ese: database size %d is not aligned to %d-byte pages", source.Size(), pageSize)
	}
	database := &Database{
		source: source,
		info:   Info{PageSize: pageSize, Revision: revision, Version: version},
		byName: make(map[string]int),
	}
	if err := database.readCatalog(); err != nil {
		return nil, err
	}
	return database, nil
}

// Info returns physical format facts from the ESE header.
func (d *Database) Info() Info { return d.info }

// Tables returns catalog tables in their stored order.
func (d *Database) Tables() []Table {
	result := make([]Table, len(d.tables))
	copy(result, d.tables)
	for index := range result {
		result[index].Columns = append([]Column(nil), result[index].Columns...)
		result[index].Indexes = append([]string(nil), result[index].Indexes...)
	}
	return result
}

// Rows walks up to maximum records from name. A zero maximum requests no
// records; a negative maximum is rejected so callers always set an explicit
// memory bound.
func (d *Database) Rows(name string, maximum int) ([]Record, error) {
	if maximum < 0 {
		return nil, fmt.Errorf("ese: maximum records must be non-negative")
	}
	index, present := d.byName[strings.ToLower(name)]
	if !present {
		return nil, fmt.Errorf("ese: table %q not found", name)
	}
	rows := make([]Record, 0, min(maximum, 1024))
	if maximum == 0 {
		return rows, nil
	}
	limitReached := fmt.Errorf("ese: record limit reached")
	table := &d.tables[index]
	err := d.walkTree(table.FatherDataPageNumber, func(value pageValue) error {
		if len(rows) >= maximum {
			return limitReached
		}
		data, err := entryData(value)
		if err != nil {
			return err
		}
		record, err := d.decodeRecord(table, data)
		if err != nil {
			return err
		}
		rows = append(rows, record)
		return nil
	})
	if err != nil && err != limitReached {
		return nil, fmt.Errorf("ese: table %q: %w", name, err)
	}
	return rows, nil
}

func (d *Database) readCatalog() error {
	current := -1
	err := d.walkTree(catalogRootPage, func(value pageValue) error {
		data, err := entryData(value)
		if err != nil {
			return fmt.Errorf("catalog entry: %w", err)
		}
		record, err := decodeCatalogRecord(data)
		if err != nil {
			return fmt.Errorf("catalog record: %w", err)
		}
		switch record.recordType {
		case 1: // table
			d.tables = append(d.tables, Table{
				FatherDataPageNumber: record.definition,
				Name:                 record.name,
			})
			current = len(d.tables) - 1
			d.byName[strings.ToLower(record.name)] = current
		case 2: // column
			if current < 0 || d.tables[current].Name == "" {
				return fmt.Errorf("column %q precedes its table", record.name)
			}
			d.tables[current].Columns = append(d.tables[current].Columns, Column{
				CodePage: record.locale, Flags: record.flags, Identifier: record.identifier,
				Name: record.name, SpaceUsage: int64(record.spaceUsage),
				Type: columnTypeName(record.definition), typeCode: record.definition,
			})
		case 3: // index
			if current < 0 {
				return fmt.Errorf("index %q precedes its table", record.name)
			}
			d.tables[current].Indexes = append(d.tables[current].Indexes, record.name)
		case 4: // long-value tree
			if current < 0 {
				return fmt.Errorf("long-value tree precedes its table")
			}
			d.tables[current].longValuePage = record.definition
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("ese: catalog: %w", err)
	}
	for index := range d.tables {
		sort.SliceStable(d.tables[index].Columns, func(left, right int) bool {
			return d.tables[index].Columns[left].Identifier < d.tables[index].Columns[right].Identifier
		})
	}
	if len(d.tables) == 0 {
		return fmt.Errorf("ese: catalog contains no tables")
	}
	return nil
}

func (d *Database) walkTree(root uint32, visit func(pageValue) error) error {
	maximumPages := uint32(d.source.Size()/d.info.PageSize - 2)
	visited := make(map[uint32]bool)
	var walk func(uint32) error
	walk = func(identifier uint32) error {
		if identifier == 0 || identifier > maximumPages {
			return fmt.Errorf("page %d is outside database", identifier)
		}
		if visited[identifier] {
			return fmt.Errorf("page tree contains cycle at %d", identifier)
		}
		visited[identifier] = true
		page, err := d.readPage(identifier)
		if err != nil {
			return err
		}
		if page.flags&pageFlagLeaf != 0 {
			for tag := uint16(1); tag < page.tags; tag++ {
				value, err := d.pageValue(page, tag)
				if err != nil {
					return err
				}
				if len(value.data) == 0 || value.flags&tagFlagDefunct != 0 {
					continue
				}
				if page.flags&(pageFlagSpaceTree|pageFlagIndex|pageFlagLongValue) != 0 {
					continue
				}
				if err := visit(value); err != nil {
					return err
				}
			}
			return nil
		}
		for tag := uint16(1); tag < page.tags; tag++ {
			value, err := d.pageValue(page, tag)
			if err != nil {
				return err
			}
			if len(value.data) == 0 || value.flags&tagFlagDefunct != 0 {
				continue
			}
			child, err := branchChild(value)
			if err != nil {
				return fmt.Errorf("page %d tag %d: %w", identifier, tag, err)
			}
			if err := walk(child); err != nil {
				return err
			}
		}
		return nil
	}
	return walk(root)
}

func (d *Database) readPage(identifier uint32) (page, error) {
	data := make([]byte, d.info.PageSize)
	offset := int64(identifier+1) * d.info.PageSize
	if _, err := readFullAt(d.source, data, offset); err != nil {
		return page{}, fmt.Errorf("page %d: %w", identifier, err)
	}
	tags := binary.LittleEndian.Uint16(data[34:36])
	if d.info.Revision >= 0x122 {
		tags &= 0x0fff
	}
	if tags == 0 || int(tags)*4 > len(data)-d.pageHeaderSize() {
		return page{}, fmt.Errorf("page %d: invalid tag count %d", identifier, tags)
	}
	return page{
		id: identifier, data: data,
		flags: binary.LittleEndian.Uint32(data[36:40]), tags: tags,
	}, nil
}

func (d *Database) pageHeaderSize() int {
	if d.info.Revision >= 0x11 && d.info.PageSize > 8192 {
		return 80
	}
	return 40

}

func (d *Database) pageValue(page page, tag uint16) (pageValue, error) {
	if tag >= page.tags {
		return pageValue{}, fmt.Errorf("page %d: tag %d is out of range", page.id, tag)
	}
	descriptor := len(page.data) - 4*int(tag+1)
	// ESE TAG descriptors store the value size first and its page-relative
	// offset second. Tags themselves are indexed from the end of the page.
	rawSize := binary.LittleEndian.Uint16(page.data[descriptor : descriptor+2])
	rawOffset := binary.LittleEndian.Uint16(page.data[descriptor+2 : descriptor+4])
	mask := uint16(0x1fff)
	if d.info.Revision >= 0x11 && d.info.PageSize > 8192 {
		mask = 0x7fff
	}
	offset := int(rawOffset & mask)
	size := int(rawSize & mask)
	start := d.pageHeaderSize() + offset
	end := start + size
	if start < d.pageHeaderSize() || end < start || end > descriptor {
		return pageValue{}, fmt.Errorf("page %d tag %d: invalid range %d:%d", page.id, tag, start, end)
	}
	flags := uint8(rawOffset >> 13)
	if mask == 0x7fff && size > 0 {
		flags = page.data[start+1] >> 5
	}
	return pageValue{data: page.data[start:end], flags: flags}, nil
}

func branchChild(value pageValue) (uint32, error) {
	offset := 0
	if value.flags&tagFlagCommon != 0 {
		offset += 2
	}
	if len(value.data) < offset+2 {
		return 0, fmt.Errorf("short branch entry")
	}
	keySize := int(binary.LittleEndian.Uint16(value.data[offset:offset+2]) & 0x1fff)
	offset += 2 + keySize
	if len(value.data) < offset+4 {
		return 0, fmt.Errorf("branch entry key exceeds value")
	}
	return binary.LittleEndian.Uint32(value.data[offset : offset+4]), nil
}

func entryData(value pageValue) ([]byte, error) {
	offset := 0
	if value.flags&tagFlagCommon != 0 {
		offset += 2
	}
	if len(value.data) < offset+2 {
		return nil, fmt.Errorf("short leaf entry")
	}
	keySize := int(binary.LittleEndian.Uint16(value.data[offset:offset+2]) & 0x1fff)
	offset += 2 + keySize
	if offset > len(value.data) {
		return nil, fmt.Errorf("leaf entry key exceeds value")
	}
	return value.data[offset:], nil
}

func decodeCatalogRecord(data []byte) (catalogRecord, error) {
	if len(data) < 4 {
		return catalogRecord{}, fmt.Errorf("short data-definition header")
	}
	lastVariable := int(data[1])
	variableOffset := int(binary.LittleEndian.Uint16(data[2:4]))
	variableCount := max(0, lastVariable-127)
	if variableOffset < 4 || variableOffset+variableCount*2 > len(data) {
		return catalogRecord{}, fmt.Errorf("invalid variable-data offset %d", variableOffset)
	}
	name := ""
	if variableCount > 0 {
		nameEnd := int(binary.LittleEndian.Uint16(data[variableOffset : variableOffset+2]))
		if nameEnd&0x8000 == 0 {
			nameStart := variableOffset + variableCount*2
			if nameEnd < 0 || nameStart+nameEnd > len(data) {
				return catalogRecord{}, fmt.Errorf("invalid catalog name size %d", nameEnd)
			}
			name = strings.TrimRight(string(data[nameStart:nameStart+nameEnd]), "\x00")
		}
	}
	if len(data) < 30 {
		return catalogRecord{}, fmt.Errorf("short catalog fixed data")
	}
	return catalogRecord{
		objectID:   binary.LittleEndian.Uint32(data[4:8]),
		recordType: binary.LittleEndian.Uint16(data[8:10]),
		identifier: binary.LittleEndian.Uint32(data[10:14]),
		definition: binary.LittleEndian.Uint32(data[14:18]),
		spaceUsage: binary.LittleEndian.Uint32(data[18:22]),
		flags:      binary.LittleEndian.Uint32(data[22:26]),
		locale:     binary.LittleEndian.Uint32(data[26:30]),
		name:       name,
	}, nil
}

func (d *Database) decodeRecord(table *Table, data []byte) (Record, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("short data-definition header")
	}
	lastFixed := uint32(data[0])
	lastVariable := uint32(data[1])
	variableOffset := int(binary.LittleEndian.Uint16(data[2:4]))
	variableCount := 0
	if lastVariable >= 128 {
		variableCount = int(lastVariable - 127)
	}
	if variableOffset < 4 || variableOffset+variableCount*2 > len(data) {
		return nil, fmt.Errorf("invalid variable-data offset %d", variableOffset)
	}
	variableEnds := make([]int, variableCount)
	lastVariableEnd := 0
	for index := range variableEnds {
		raw := int(binary.LittleEndian.Uint16(data[variableOffset+index*2 : variableOffset+index*2+2]))
		variableEnds[index] = raw
		if raw&0x8000 == 0 {
			lastVariableEnd = raw
		}
	}
	variableData := variableOffset + variableCount*2
	taggedStart := variableData + lastVariableEnd
	if taggedStart > len(data) {
		return nil, fmt.Errorf("variable data exceeds record")
	}
	tagged, err := d.decodeTaggedValues(data[taggedStart:])
	if err != nil {
		return nil, err
	}
	fixedOffset := 4
	fixedNullBytes := (int(lastFixed) + 7) / 8
	if variableOffset < fixedOffset+fixedNullBytes {
		return nil, fmt.Errorf("fixed null bitmap exceeds record")
	}
	fixedNulls := data[variableOffset-fixedNullBytes : variableOffset]
	record := make(Record, 0, len(table.Columns))
	for _, column := range table.Columns {
		var raw []byte
		present := false
		switch {
		case column.Identifier <= lastFixed:
			end := fixedOffset + int(column.SpaceUsage)
			if end > variableOffset-len(fixedNulls) || end > len(data) {
				return nil, fmt.Errorf("column %q fixed data exceeds record", column.Name)
			}
			raw = data[fixedOffset:end]
			index := column.Identifier - 1
			present = fixedNulls[index/8]&(1<<(index%8)) == 0
			fixedOffset = end
		case column.Identifier >= 128 && column.Identifier <= lastVariable:
			index := int(column.Identifier - 128)
			endRaw := variableEnds[index]
			if endRaw&0x8000 != 0 {
				break
			}
			start := 0
			for previous := index - 1; previous >= 0; previous-- {
				if variableEnds[previous]&0x8000 == 0 {
					start = variableEnds[previous]
					break
				}
			}
			end := endRaw & 0x7fff
			if end < start || variableData+end > len(data) {
				return nil, fmt.Errorf("column %q variable data exceeds record", column.Name)
			}
			raw, present = data[variableData+start:variableData+end], true
		case column.Identifier >= 256:
			value, ok := tagged[column.Identifier]
			if ok {
				raw, present = value.data, true
				if value.flags&0x08 != 0 {
					parts, err := decodeMultiValue(raw, value.flags&0x10 != 0)
					if err != nil {
						return nil, fmt.Errorf("column %q: %w", column.Name, err)
					}
					values := make([]any, 0, len(parts))
					for _, part := range parts {
						values = append(values, decodeColumnValue(column, part))
					}
					record = append(record, Field{Name: column.Name, Value: values})
					continue
				}
			}
		}
		if present {
			record = append(record, Field{Name: column.Name, Value: decodeColumnValue(column, raw)})
		}
	}
	return record, nil
}

type taggedValue struct {
	data  []byte
	flags uint8
}

func (d *Database) decodeTaggedValues(data []byte) (map[uint32]taggedValue, error) {
	result := make(map[uint32]taggedValue)
	if len(data) < 4 {
		return result, nil
	}
	first := int(binary.LittleEndian.Uint16(data[2:4]) & 0x7fff)
	if first == 0 || first%4 != 0 || first > len(data) {
		return nil, fmt.Errorf("invalid tagged-value directory size %d", first)
	}
	count := first / 4
	for index := 0; index < count; index++ {
		directory := index * 4
		identifier := uint32(binary.LittleEndian.Uint16(data[directory : directory+2]))
		rawStart := binary.LittleEndian.Uint16(data[directory+2 : directory+4])
		start := int(rawStart & 0x7fff)
		end := len(data)
		if index+1 < count {
			end = int(binary.LittleEndian.Uint16(data[directory+6:directory+8]) & 0x7fff)
		}
		if start < first || end < start || end > len(data) {
			return nil, fmt.Errorf("tagged value %d has invalid range %d:%d", identifier, start, end)
		}
		flags := uint8(0)
		if d.info.Revision >= 0x11 && d.info.PageSize > 8192 || rawStart&0x4000 != 0 {
			if start == end {
				continue
			}
			flags = data[start]
			start++
		}
		result[identifier] = taggedValue{data: data[start:end], flags: flags}
	}
	return result, nil
}

func decodeMultiValue(data []byte, sized bool) ([][]byte, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("short multi-value data")
	}
	first := int(binary.LittleEndian.Uint16(data[:2]) & 0x7fff)
	if first < 2 || first%2 != 0 || first > len(data) {
		return nil, fmt.Errorf("invalid multi-value directory size %d", first)
	}
	count := first / 2
	result := make([][]byte, 0, count)
	for index := 0; index < count; index++ {
		start := int(binary.LittleEndian.Uint16(data[index*2:index*2+2]) & 0x7fff)
		end := len(data)
		if index+1 < count {
			end = int(binary.LittleEndian.Uint16(data[index*2+2:index*2+4]) & 0x7fff)
		}
		if sized {
			end = start
			if start+2 <= len(data) {
				end = start + 2 + int(binary.LittleEndian.Uint16(data[start:start+2]))
				start += 2
			}
		}
		if start < first || end < start || end > len(data) {
			return nil, fmt.Errorf("invalid multi-value range %d:%d", start, end)
		}
		result = append(result, data[start:end])
	}
	return result, nil
}

func decodeColumnValue(column Column, data []byte) any {
	switch column.typeCode {
	case 1:
		return len(data) > 0 && data[0] != 0
	case 2:
		if len(data) >= 1 {
			return uint8(data[0])
		}
	case 3:
		if len(data) >= 2 {
			return int16(binary.LittleEndian.Uint16(data))
		}
	case 4:
		if len(data) >= 4 {
			return int32(binary.LittleEndian.Uint32(data))
		}
	case 5, 15:
		if len(data) >= 8 {
			return int64(binary.LittleEndian.Uint64(data))
		}
	case 6:
		if len(data) >= 4 {
			return math.Float32frombits(binary.LittleEndian.Uint32(data))
		}
	case 7:
		if len(data) >= 8 {
			return math.Float64frombits(binary.LittleEndian.Uint64(data))
		}
	case 8:
		if len(data) >= 8 {
			if column.Flags&1 != 0 {
				return windowsFileTime(binary.LittleEndian.Uint64(data))
			}
			return math.Float64frombits(binary.LittleEndian.Uint64(data))
		}
	case 10, 12:
		return decodeText(data, column.CodePage)
	case 14:
		if len(data) >= 4 {
			return binary.LittleEndian.Uint32(data)
		}
	case 16:
		if len(data) >= 16 {
			return decodeGUID(data)
		}
	case 17:
		if len(data) >= 2 {
			return binary.LittleEndian.Uint16(data)
		}
	}
	return append([]byte(nil), data...)
}

func decodeText(data []byte, codePage uint32) string {
	if codePage != 1200 {
		return strings.TrimRight(string(data), "\x00")
	}
	words := make([]uint16, len(data)/2)
	for index := range words {
		words[index] = binary.LittleEndian.Uint16(data[index*2 : index*2+2])
	}
	return strings.TrimRight(string(utf16.Decode(words)), "\x00")
}

func decodeGUID(data []byte) string {
	return fmt.Sprintf("%08x-%04x-%04x-%02x%02x-%x",
		binary.LittleEndian.Uint32(data[0:4]), binary.LittleEndian.Uint16(data[4:6]),
		binary.LittleEndian.Uint16(data[6:8]), data[8], data[9], data[10:16])
}

func windowsFileTime(value uint64) time.Time {
	const unixEpoch = 116444736000000000
	if value < unixEpoch {
		return time.Time{}
	}
	return time.Unix(0, int64(value-unixEpoch)*100).UTC()
}

func columnTypeName(value uint32) string {
	names := map[uint32]string{
		0: "Nil", 1: "Boolean", 2: "Unsigned byte", 3: "Signed short",
		4: "Signed long", 5: "Currency", 6: "Single precision FP",
		7: "Double precision FP", 8: "DateTime", 9: "Binary", 10: "Text",
		11: "Long Binary", 12: "Long Text", 13: "Super Long Value",
		14: "Unsigned long", 15: "Long long", 16: "GUID", 17: "Unsigned short",
	}
	if name, present := names[value]; present {
		return name
	}
	return fmt.Sprintf("Unknown(%d)", value)
}

func readFullAt(reader io.ReaderAt, data []byte, offset int64) (int, error) {
	total := 0
	for total < len(data) {
		count, err := reader.ReadAt(data[total:], offset+int64(total))
		total += count
		if err != nil {
			if err == io.EOF && total == len(data) {
				return total, nil
			}
			return total, err
		}
		if count == 0 {
			return total, io.ErrNoProgress
		}
	}
	return total, nil
}
