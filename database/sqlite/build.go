package sqlite

import (
	"encoding/binary"
	"fmt"
	"math"
	"unicode/utf16"

	starfile "github.com/tinyrange/trex/storage/star"
)

// Object describes one sqlite_schema object. Table rows require RowID; index
// rows contain the complete, already-collated index record including the
// referenced table key. Views and triggers have no rows or root page.
type Object struct {
	Type      string
	Name      string
	TableName string
	SQL       string
	Rows      []Row
}

// BuildOptions selects portable SQLite file-format properties.
type BuildOptions struct {
	PageSize      int
	Encoding      uint32
	UserVersion   uint32
	ApplicationID uint32
}

type buildObject struct {
	definition Object
	root       uint32
}

type buildPage struct {
	number uint32
	last   int64
}

type sqliteBuilder struct {
	options BuildOptions
	pages   [][]byte
}

// Build creates a clean SQLite 3 database directly in memory. It implements
// the record, overflow, table-btree, and index-btree formats without invoking
// a SQLite library or process.
func Build(objects []Object, options BuildOptions) (*starfile.Bytes, error) {
	if options.PageSize == 0 {
		options.PageSize = 4096
	}
	if options.Encoding == 0 {
		options.Encoding = 1
	}
	if options.PageSize < minimumPageSize || options.PageSize > maximumPageSize || options.PageSize&(options.PageSize-1) != 0 {
		return nil, fmt.Errorf("sqlite: invalid writer page size %d", options.PageSize)
	}
	if options.Encoding < 1 || options.Encoding > 3 {
		return nil, fmt.Errorf("sqlite: invalid writer encoding %d", options.Encoding)
	}
	builder := &sqliteBuilder{options: options}
	builder.allocate() // sqlite_schema always owns page 1.
	prepared := make([]buildObject, len(objects))
	seen := make(map[string]bool)
	for index, object := range objects {
		if object.Name == "" || object.Type == "" {
			return nil, fmt.Errorf("sqlite: object %d has an empty type or name", index)
		}
		if seen[object.Name] {
			return nil, fmt.Errorf("sqlite: duplicate schema object %q", object.Name)
		}
		seen[object.Name] = true
		if object.TableName == "" {
			object.TableName = object.Name
		}
		prepared[index].definition = object
		switch object.Type {
		case "table", "index":
			prepared[index].root = builder.allocate()
		case "view", "trigger":
			if len(object.Rows) != 0 {
				return nil, fmt.Errorf("sqlite: %s %q cannot contain b-tree rows", object.Type, object.Name)
			}
		default:
			return nil, fmt.Errorf("sqlite: unsupported schema object type %q", object.Type)
		}
	}
	for _, object := range prepared {
		var err error
		switch object.definition.Type {
		case "table":
			err = builder.buildTable(object.root, object.definition.Rows, false)
		case "index":
			err = builder.buildIndex(object.root, object.definition.Rows)
		}
		if err != nil {
			return nil, fmt.Errorf("sqlite: build %s %q: %w", object.definition.Type, object.definition.Name, err)
		}
	}
	schema := make([]Row, 0, len(prepared))
	for index, object := range prepared {
		rowID := int64(index + 1)
		schema = append(schema, Row{RowID: &rowID, Values: []any{
			object.definition.Type,
			object.definition.Name,
			object.definition.TableName,
			int64(object.root),
			object.definition.SQL,
		}})
	}
	if err := builder.buildTable(1, schema, true); err != nil {
		return nil, fmt.Errorf("sqlite: build schema: %w", err)
	}
	if len(builder.pages) > maximumPages {
		return nil, fmt.Errorf("sqlite: generated page count %d exceeds limit", len(builder.pages))
	}
	builder.writeHeader()
	data := make([]byte, len(builder.pages)*options.PageSize)
	for index, page := range builder.pages {
		copy(data[index*options.PageSize:], page)
	}
	return &starfile.Bytes{Name: "sqlite", Data: data}, nil
}

func (b *sqliteBuilder) allocate() uint32 {
	b.pages = append(b.pages, make([]byte, b.options.PageSize))
	return uint32(len(b.pages))
}

func (b *sqliteBuilder) page(number uint32) []byte { return b.pages[number-1] }

func (b *sqliteBuilder) buildTable(root uint32, rows []Row, schema bool) error {
	previous := int64(math.MinInt64)
	for index, row := range rows {
		if row.RowID == nil {
			return fmt.Errorf("row %d has no rowid", index)
		}
		if index != 0 && *row.RowID <= previous {
			return fmt.Errorf("rowids are not strictly increasing at row %d", index)
		}
		previous = *row.RowID
	}
	headerOffset := 0
	if schema {
		headerOffset = 100
	}
	if len(rows) == 0 {
		return b.writeBtreePage(root, headerOffset, 0x0d, 0, nil)
	}
	if len(rows) == 1 {
		cell, err := b.tableLeafCell(rows[0])
		if err != nil {
			return err
		}
		return b.writeBtreePage(root, headerOffset, 0x0d, 0, [][]byte{cell})
	}
	level := make([]buildPage, 0, len(rows))
	for _, row := range rows {
		number := b.allocate()
		cell, err := b.tableLeafCell(row)
		if err != nil {
			return err
		}
		if err := b.writeBtreePage(number, 0, 0x0d, 0, [][]byte{cell}); err != nil {
			return err
		}
		level = append(level, buildPage{number: number, last: *row.RowID})
	}
	for len(level) > 20 {
		next := make([]buildPage, 0, (len(level)+19)/20)
		for start := 0; start < len(level); {
			count := min(20, len(level)-start)
			// Non-root interior pages require at least two keys, hence at
			// least three children. Redistribute the final 21 or 22 children
			// so that the last page is not underfull.
			if len(level)-start == 21 {
				count = 18
			} else if len(level)-start == 22 {
				count = 19
			}
			end := start + count
			number := b.allocate()
			if err := b.writeTableInterior(number, 0, level[start:end]); err != nil {
				return err
			}
			next = append(next, buildPage{number: number, last: level[end-1].last})
			start = end
		}
		level = next
	}
	return b.writeTableInterior(root, headerOffset, level)
}

func (b *sqliteBuilder) writeTableInterior(number uint32, headerOffset int, children []buildPage) error {
	if len(children) < 2 {
		return fmt.Errorf("interior table page needs at least two children")
	}
	cells := make([][]byte, 0, len(children)-1)
	for _, child := range children[:len(children)-1] {
		cell := make([]byte, 4)
		binary.BigEndian.PutUint32(cell, child.number)
		cell = append(cell, encodeVarint(uint64(child.last))...)
		cells = append(cells, cell)
	}
	return b.writeBtreePage(number, headerOffset, 0x05, children[len(children)-1].number, cells)
}

func (b *sqliteBuilder) buildIndex(root uint32, rows []Row) error {
	for index, row := range rows {
		if row.RowID != nil {
			return fmt.Errorf("index row %d unexpectedly has a rowid", index)
		}
	}
	return b.buildIndexNode(root, rows)
}

func (b *sqliteBuilder) buildIndexNode(number uint32, rows []Row) error {
	leafBytes := 0
	for _, row := range rows {
		size, err := b.indexCellSize(row)
		if err != nil {
			return err
		}
		leafBytes += size
	}
	if 8+len(rows)*2+leafBytes <= b.options.PageSize {
		cells := make([][]byte, 0, len(rows))
		for _, row := range rows {
			cell, err := b.indexCell(row)
			if err != nil {
				return err
			}
			cells = append(cells, cell)
		}
		return b.writeBtreePage(number, 0, 0x0a, 0, cells)
	}
	if len(rows) < 5 {
		return fmt.Errorf("four index records cannot fit one page")
	}
	// Non-root SQLite index interior pages require at least two keys. Split
	// into three non-empty children and promote two records instead of
	// recursively creating one-key interior pages.
	first, second := len(rows)/3, 2*len(rows)/3
	left, middle, right := b.allocate(), b.allocate(), b.allocate()
	if err := b.buildIndexNode(left, rows[:first]); err != nil {
		return err
	}
	if err := b.buildIndexNode(middle, rows[first+1:second]); err != nil {
		return err
	}
	if err := b.buildIndexNode(right, rows[second+1:]); err != nil {
		return err
	}
	firstCell, err := b.indexCell(rows[first])
	if err != nil {
		return err
	}
	secondCell, err := b.indexCell(rows[second])
	if err != nil {
		return err
	}
	leftInterior := make([]byte, 4)
	binary.BigEndian.PutUint32(leftInterior, left)
	leftInterior = append(leftInterior, firstCell...)
	middleInterior := make([]byte, 4)
	binary.BigEndian.PutUint32(middleInterior, middle)
	middleInterior = append(middleInterior, secondCell...)
	return b.writeBtreePage(number, 0, 0x02, right, [][]byte{leftInterior, middleInterior})
}

func (b *sqliteBuilder) indexCellSize(row Row) (int, error) {
	payload, err := encodeRecord(row.Values, b.options.Encoding)
	if err != nil {
		return 0, err
	}
	usable := b.options.PageSize
	maximumLocal := ((usable - 12) * 64 / 255) - 23
	local := len(payload)
	if len(payload) > maximumLocal {
		minimumLocal := ((usable - 12) * 32 / 255) - 23
		local = minimumLocal + (len(payload)-minimumLocal)%(usable-4)
		if local > maximumLocal {
			local = minimumLocal
		}
	}
	overflow := 0
	if local != len(payload) {
		overflow = 4
	}
	return len(encodeVarint(uint64(len(payload)))) + local + overflow, nil
}

func (b *sqliteBuilder) tableLeafCell(row Row) ([]byte, error) {
	payload, err := encodeRecord(row.Values, b.options.Encoding)
	if err != nil {
		return nil, err
	}
	prefix := append(encodeVarint(uint64(len(payload))), encodeVarint(uint64(*row.RowID))...)
	return b.payloadCell(prefix, payload, true)
}

func (b *sqliteBuilder) indexCell(row Row) ([]byte, error) {
	payload, err := encodeRecord(row.Values, b.options.Encoding)
	if err != nil {
		return nil, err
	}
	return b.payloadCell(encodeVarint(uint64(len(payload))), payload, false)
}

func (b *sqliteBuilder) payloadCell(prefix, payload []byte, tableLeaf bool) ([]byte, error) {
	usable := b.options.PageSize
	maximumLocal := ((usable - 12) * 64 / 255) - 23
	if tableLeaf {
		maximumLocal = usable - 35
	}
	local := len(payload)
	if len(payload) > maximumLocal {
		minimumLocal := ((usable - 12) * 32 / 255) - 23
		local = minimumLocal + (len(payload)-minimumLocal)%(usable-4)
		if local > maximumLocal {
			local = minimumLocal
		}
	}
	cell := append(append([]byte{}, prefix...), payload[:local]...)
	if local == len(payload) {
		return cell, nil
	}
	first, previous := uint32(0), uint32(0)
	remaining := payload[local:]
	for len(remaining) != 0 {
		number := b.allocate()
		if first == 0 {
			first = number
		}
		if previous != 0 {
			binary.BigEndian.PutUint32(b.page(previous)[:4], number)
		}
		count := min(len(remaining), usable-4)
		copy(b.page(number)[4:], remaining[:count])
		remaining = remaining[count:]
		previous = number
	}
	pointer := make([]byte, 4)
	binary.BigEndian.PutUint32(pointer, first)
	return append(cell, pointer...), nil
}

func (b *sqliteBuilder) writeBtreePage(number uint32, headerOffset int, pageType byte, right uint32, cells [][]byte) error {
	page := b.page(number)
	clear(page[headerOffset:])
	headerSize := 8
	if pageType == 0x02 || pageType == 0x05 {
		headerSize = 12
		binary.BigEndian.PutUint32(page[headerOffset+8:headerOffset+12], right)
	}
	pointers := headerOffset + headerSize
	content := len(page)
	for index, cell := range cells {
		content -= len(cell)
		if content < pointers+len(cells)*2 {
			return fmt.Errorf("page %d cells exceed page size", number)
		}
		copy(page[content:], cell)
		binary.BigEndian.PutUint16(page[pointers+index*2:pointers+index*2+2], uint16(content))
	}
	page[headerOffset] = pageType
	binary.BigEndian.PutUint16(page[headerOffset+3:headerOffset+5], uint16(len(cells)))
	contentOffset := uint16(content)
	if b.options.PageSize == maximumPageSize && content == maximumPageSize {
		contentOffset = 0
	}
	binary.BigEndian.PutUint16(page[headerOffset+5:headerOffset+7], contentOffset)
	return nil
}

func (b *sqliteBuilder) writeHeader() {
	header := b.pages[0]
	copy(header[:16], databaseMagic)
	pageSize := uint16(b.options.PageSize)
	if b.options.PageSize == maximumPageSize {
		pageSize = 1
	}
	binary.BigEndian.PutUint16(header[16:18], pageSize)
	header[18], header[19], header[20] = 1, 1, 0
	header[21], header[22], header[23] = 64, 32, 32
	binary.BigEndian.PutUint32(header[24:28], 1)
	binary.BigEndian.PutUint32(header[28:32], uint32(len(b.pages)))
	binary.BigEndian.PutUint32(header[40:44], 1)
	binary.BigEndian.PutUint32(header[44:48], 4)
	binary.BigEndian.PutUint32(header[56:60], b.options.Encoding)
	binary.BigEndian.PutUint32(header[60:64], b.options.UserVersion)
	binary.BigEndian.PutUint32(header[68:72], b.options.ApplicationID)
	binary.BigEndian.PutUint32(header[92:96], 1)
	binary.BigEndian.PutUint32(header[96:100], 3046000)
}

func encodeRecord(values []any, encoding uint32) ([]byte, error) {
	serials := make([]byte, 0, len(values))
	body := make([]byte, 0)
	for index, value := range values {
		serial, field, err := encodeField(value, encoding)
		if err != nil {
			return nil, fmt.Errorf("field %d: %w", index, err)
		}
		serials = append(serials, encodeVarint(serial)...)
		body = append(body, field...)
	}
	headerSize := len(serials) + 1
	for len(encodeVarint(uint64(headerSize)))+len(serials) != headerSize {
		headerSize = len(encodeVarint(uint64(headerSize))) + len(serials)
	}
	record := append(encodeVarint(uint64(headerSize)), serials...)
	return append(record, body...), nil
}

func encodeField(value any, encoding uint32) (uint64, []byte, error) {
	switch value := value.(type) {
	case nil:
		return 0, nil, nil
	case bool:
		if value {
			return 9, nil, nil
		}
		return 8, nil, nil
	case int:
		return encodeInteger(int64(value))
	case int64:
		return encodeInteger(value)
	case uint64:
		if value > math.MaxInt64 {
			return 0, nil, fmt.Errorf("unsigned integer %d exceeds SQLite signed range", value)
		}
		return encodeInteger(int64(value))
	case float64:
		field := make([]byte, 8)
		binary.BigEndian.PutUint64(field, math.Float64bits(value))
		return 7, field, nil
	case []byte:
		return 12 + uint64(len(value))*2, append([]byte(nil), value...), nil
	case string:
		field, err := encodeText(value, encoding)
		if err != nil {
			return 0, nil, err
		}
		return 13 + uint64(len(field))*2, field, nil
	default:
		return 0, nil, fmt.Errorf("unsupported SQLite value type %T", value)
	}
}

func encodeInteger(value int64) (uint64, []byte, error) {
	if value == 0 {
		return 8, nil, nil
	}
	if value == 1 {
		return 9, nil, nil
	}
	sizes := []struct {
		serial uint64
		bytes  int
		min    int64
		max    int64
	}{{1, 1, -128, 127}, {2, 2, -32768, 32767}, {3, 3, -8388608, 8388607}, {4, 4, math.MinInt32, math.MaxInt32}, {5, 6, -140737488355328, 140737488355327}, {6, 8, math.MinInt64, math.MaxInt64}}
	for _, size := range sizes {
		if value < size.min || value > size.max {
			continue
		}
		field := make([]byte, size.bytes)
		unsigned := uint64(value)
		for index := size.bytes - 1; index >= 0; index-- {
			field[index] = byte(unsigned)
			unsigned >>= 8
		}
		return size.serial, field, nil
	}
	panic("all int64 values fit serial type 6")
}

func encodeText(value string, encoding uint32) ([]byte, error) {
	if encoding == 1 {
		return []byte(value), nil
	}
	units := utf16.Encode([]rune(value))
	data := make([]byte, len(units)*2)
	order := binary.ByteOrder(binary.LittleEndian)
	if encoding == 3 {
		order = binary.BigEndian
	}
	for index, unit := range units {
		order.PutUint16(data[index*2:index*2+2], unit)
	}
	return data, nil
}

func encodeVarint(value uint64) []byte {
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
