// Package sqlite reads SQLite 3 databases and write-ahead logs directly from
// portable TinyRange storage readers.
package sqlite

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"strings"

	"github.com/tinyrange/trex/storage"
)

const (
	minimumPageSize = 512
	maximumPageSize = 65536
	maximumPages    = 1 << 20
	maximumDepth    = 128
)

var databaseMagic = []byte("SQLite format 3\x00")

// Info describes the effective database after applying the last committed WAL
// transaction.
type Info struct {
	PageSize      int
	PageCount     uint32
	Encoding      uint32
	UserVersion   uint32
	ApplicationID uint32
	WALFrames     int
}

// SchemaEntry is one row from sqlite_schema.
type SchemaEntry struct {
	Type      string
	Name      string
	TableName string
	RootPage  uint32
	SQL       string
}

// Row is one logical b-tree record. Index b-trees have no RowID.
type Row struct {
	RowID  *int64
	Values []any
}

type walFrame struct {
	pageNumber uint32
	data       []byte
}

// Database is a bounded SQLite reader backed by a random-access source.
type Database struct {
	source   storage.Reader
	info     Info
	reserved int
	usable   int
	pages    map[uint32][]byte
	schema   []SchemaEntry
}

// Open parses a SQLite database and optionally overlays the last committed
// transaction from wal. No native SQLite library or host filesystem is used.
func Open(source storage.Reader, wal storage.Reader) (*Database, error) {
	if source == nil {
		return nil, fmt.Errorf("sqlite: source is nil")
	}
	header := make([]byte, 100)
	if _, err := readFullAt(source, header, 0); err != nil {
		return nil, fmt.Errorf("sqlite: header: %w", err)
	}
	if string(header[:16]) != string(databaseMagic) {
		return nil, fmt.Errorf("sqlite: invalid database signature")
	}
	pageSize := int(binary.BigEndian.Uint16(header[16:18]))
	if pageSize == 1 {
		pageSize = maximumPageSize
	}
	if pageSize < minimumPageSize || pageSize > maximumPageSize || pageSize&(pageSize-1) != 0 {
		return nil, fmt.Errorf("sqlite: invalid page size %d", pageSize)
	}
	reserved := int(header[20])
	if reserved >= pageSize || pageSize-reserved < 480 {
		return nil, fmt.Errorf("sqlite: invalid reserved space %d", reserved)
	}
	encoding := binary.BigEndian.Uint32(header[56:60])
	if encoding < 1 || encoding > 3 {
		return nil, fmt.Errorf("sqlite: unsupported text encoding %d", encoding)
	}
	pageCount := binary.BigEndian.Uint32(header[28:32])
	physicalPages := source.Size() / int64(pageSize)
	if pageCount == 0 {
		pageCount = uint32(physicalPages)
	}
	if pageCount == 0 || pageCount > maximumPages || int64(pageCount) > physicalPages {
		return nil, fmt.Errorf("sqlite: invalid database page count %d for %d physical pages", pageCount, physicalPages)
	}
	database := &Database{
		source: source,
		info: Info{
			PageSize:      pageSize,
			PageCount:     pageCount,
			Encoding:      encoding,
			UserVersion:   binary.BigEndian.Uint32(header[60:64]),
			ApplicationID: binary.BigEndian.Uint32(header[68:72]),
		},
		reserved: reserved,
		usable:   pageSize - reserved,
		pages:    make(map[uint32][]byte),
	}
	if wal != nil && wal.Size() != 0 {
		frames, committedPages, err := parseWAL(wal, pageSize)
		if err != nil {
			return nil, err
		}
		if committedPages != 0 {
			if committedPages > maximumPages {
				return nil, fmt.Errorf("sqlite: WAL commits invalid page count %d", committedPages)
			}
			database.info.PageCount = committedPages
			for _, frame := range frames {
				if frame.pageNumber <= committedPages {
					database.pages[frame.pageNumber] = frame.data
				}
			}
			database.info.WALFrames = len(frames)
		}
	}
	effectiveHeader, err := database.page(1)
	if err != nil {
		return nil, err
	}
	if string(effectiveHeader[:16]) != string(databaseMagic) {
		return nil, fmt.Errorf("sqlite: effective page 1 has invalid signature")
	}
	database.info.Encoding = binary.BigEndian.Uint32(effectiveHeader[56:60])
	database.info.UserVersion = binary.BigEndian.Uint32(effectiveHeader[60:64])
	database.info.ApplicationID = binary.BigEndian.Uint32(effectiveHeader[68:72])
	if database.info.Encoding < 1 || database.info.Encoding > 3 {
		return nil, fmt.Errorf("sqlite: effective page 1 has unsupported text encoding %d", database.info.Encoding)
	}
	schemaRows, err := database.btreeRows(1, 100000)
	if err != nil {
		return nil, fmt.Errorf("sqlite: schema: %w", err)
	}
	for _, row := range schemaRows {
		if len(row.Values) != 5 {
			return nil, fmt.Errorf("sqlite: schema row has %d values, want 5", len(row.Values))
		}
		typeName, okType := row.Values[0].(string)
		name, okName := row.Values[1].(string)
		tableName, okTable := row.Values[2].(string)
		root, okRoot := sqliteUint32(row.Values[3])
		if !okType || !okName || !okTable || !okRoot {
			return nil, fmt.Errorf("sqlite: malformed schema row")
		}
		sql := ""
		if row.Values[4] != nil {
			var ok bool
			sql, ok = row.Values[4].(string)
			if !ok {
				return nil, fmt.Errorf("sqlite: schema SQL for %q is not text", name)
			}
		}
		database.schema = append(database.schema, SchemaEntry{Type: typeName, Name: name, TableName: tableName, RootPage: root, SQL: sql})
	}
	return database, nil
}

// Info returns physical and transactional database facts.
func (d *Database) Info() Info { return d.info }

// Schema returns a copy of sqlite_schema in row order.
func (d *Database) Schema() []SchemaEntry {
	return append([]SchemaEntry(nil), d.schema...)
}

// Rows returns up to maximum logical rows from a named table or index.
func (d *Database) Rows(name string, maximum int) ([]Row, error) {
	if maximum < 0 || maximum > 1000000 {
		return nil, fmt.Errorf("sqlite: invalid row limit %d", maximum)
	}
	for _, entry := range d.schema {
		if strings.EqualFold(entry.Name, name) {
			if entry.RootPage == 0 {
				return nil, fmt.Errorf("sqlite: schema object %q has no b-tree", name)
			}
			return d.btreeRows(entry.RootPage, maximum)
		}
	}
	return nil, fmt.Errorf("sqlite: no schema object named %q", name)
}

func (d *Database) page(number uint32) ([]byte, error) {
	if number == 0 || number > d.info.PageCount {
		return nil, fmt.Errorf("sqlite: page %d outside database size %d", number, d.info.PageCount)
	}
	if page := d.pages[number]; page != nil {
		return page, nil
	}
	page := make([]byte, d.info.PageSize)
	offset := int64(number-1) * int64(d.info.PageSize)
	if _, err := readFullAt(d.source, page, offset); err != nil {
		return nil, fmt.Errorf("sqlite: page %d: %w", number, err)
	}
	return page, nil
}

func (d *Database) btreeRows(root uint32, maximum int) ([]Row, error) {
	rows := make([]Row, 0)
	visited := make(map[uint32]bool)
	var walk func(uint32, int) error
	walk = func(number uint32, depth int) error {
		if len(rows) >= maximum {
			return nil
		}
		if depth > maximumDepth {
			return fmt.Errorf("b-tree exceeds maximum depth %d", maximumDepth)
		}
		if visited[number] {
			return fmt.Errorf("b-tree contains repeated page %d", number)
		}
		visited[number] = true
		page, err := d.page(number)
		if err != nil {
			return err
		}
		headerOffset := 0
		if number == 1 {
			headerOffset = 100
		}
		if headerOffset+8 > d.usable {
			return fmt.Errorf("page %d has truncated b-tree header", number)
		}
		pageType := page[headerOffset]
		cellCount := int(binary.BigEndian.Uint16(page[headerOffset+3 : headerOffset+5]))
		headerSize := 8
		if pageType == 0x02 || pageType == 0x05 {
			headerSize = 12
		}
		pointers := headerOffset + headerSize
		if cellCount < 0 || pointers+cellCount*2 > d.usable {
			return fmt.Errorf("page %d cell pointer array exceeds page", number)
		}
		switch pageType {
		case 0x05:
			for index := 0; index < cellCount; index++ {
				cell, err := d.cellOffset(page, pointers, index, number)
				if err != nil {
					return err
				}
				if cell+4 > d.usable {
					return fmt.Errorf("page %d interior cell is truncated", number)
				}
				if err := walk(binary.BigEndian.Uint32(page[cell:cell+4]), depth+1); err != nil {
					return err
				}
			}
			return walk(binary.BigEndian.Uint32(page[headerOffset+8:headerOffset+12]), depth+1)
		case 0x02:
			for index := 0; index < cellCount; index++ {
				cell, err := d.cellOffset(page, pointers, index, number)
				if err != nil {
					return err
				}
				if cell+4 > d.usable {
					return fmt.Errorf("page %d interior index cell is truncated", number)
				}
				if err := walk(binary.BigEndian.Uint32(page[cell:cell+4]), depth+1); err != nil {
					return err
				}
				if len(rows) >= maximum {
					return nil
				}
				payloadSize, used, err := decodeVarint(page, cell+4, d.usable)
				if err != nil {
					return fmt.Errorf("page %d interior index cell %d payload: %w", number, index, err)
				}
				payload, err := d.cellPayload(page, cell+4+used, payloadSize, false)
				if err != nil {
					return fmt.Errorf("page %d interior index cell %d: %w", number, index, err)
				}
				values, err := decodeRecord(payload, d.info.Encoding)
				if err != nil {
					return fmt.Errorf("page %d interior index cell %d record: %w", number, index, err)
				}
				rows = append(rows, Row{Values: values})
			}
			if len(rows) >= maximum {
				return nil
			}
			return walk(binary.BigEndian.Uint32(page[headerOffset+8:headerOffset+12]), depth+1)
		case 0x0d, 0x0a:
			for index := 0; index < cellCount && len(rows) < maximum; index++ {
				cell, err := d.cellOffset(page, pointers, index, number)
				if err != nil {
					return err
				}
				position := cell
				payloadSize, used, err := decodeVarint(page, position, d.usable)
				if err != nil {
					return fmt.Errorf("page %d cell %d payload: %w", number, index, err)
				}
				position += used
				var rowID *int64
				if pageType == 0x0d {
					value, count, err := decodeVarint(page, position, d.usable)
					if err != nil {
						return fmt.Errorf("page %d cell %d rowid: %w", number, index, err)
					}
					position += count
					signed := int64(value)
					rowID = &signed
				}
				payload, err := d.cellPayload(page, position, payloadSize, pageType == 0x0d)
				if err != nil {
					return fmt.Errorf("page %d cell %d: %w", number, index, err)
				}
				values, err := decodeRecord(payload, d.info.Encoding)
				if err != nil {
					return fmt.Errorf("page %d cell %d record: %w", number, index, err)
				}
				rows = append(rows, Row{RowID: rowID, Values: values})
			}
			return nil
		default:
			return fmt.Errorf("page %d has unsupported b-tree type %#x", number, pageType)
		}
	}
	if maximum == 0 {
		return rows, nil
	}
	if err := walk(root, 0); err != nil {
		return nil, err
	}
	return rows, nil
}

func (d *Database) cellOffset(page []byte, pointers, index int, number uint32) (int, error) {
	offset := int(binary.BigEndian.Uint16(page[pointers+index*2 : pointers+index*2+2]))
	if offset < 0 || offset >= d.usable {
		return 0, fmt.Errorf("page %d cell %d offset %d exceeds usable page", number, index, offset)
	}
	return offset, nil
}

func (d *Database) cellPayload(page []byte, position int, payloadSize uint64, tableLeaf bool) ([]byte, error) {
	if payloadSize > 1<<30 {
		return nil, fmt.Errorf("payload size %d exceeds limit", payloadSize)
	}
	payloadBytes := int(payloadSize)
	maxLocal := ((d.usable - 12) * 64 / 255) - 23
	if tableLeaf {
		maxLocal = d.usable - 35
	}
	local := payloadBytes
	if payloadBytes > maxLocal {
		minimum := ((d.usable - 12) * 32 / 255) - 23
		local = minimum + (payloadBytes-minimum)%(d.usable-4)
		if local > maxLocal {
			local = minimum
		}
	}
	if position < 0 || local < 0 || position+local > d.usable {
		return nil, fmt.Errorf("local payload exceeds b-tree page")
	}
	output := make([]byte, 0, payloadBytes)
	output = append(output, page[position:position+local]...)
	if local == payloadBytes {
		return output, nil
	}
	if position+local+4 > d.usable {
		return nil, fmt.Errorf("overflow pointer exceeds b-tree page")
	}
	next := binary.BigEndian.Uint32(page[position+local : position+local+4])
	seen := make(map[uint32]bool)
	for len(output) < payloadBytes {
		if next == 0 || seen[next] {
			return nil, fmt.Errorf("invalid overflow chain at page %d", next)
		}
		seen[next] = true
		overflow, err := d.page(next)
		if err != nil {
			return nil, err
		}
		next = binary.BigEndian.Uint32(overflow[:4])
		count := min(payloadBytes-len(output), d.usable-4)
		output = append(output, overflow[4:4+count]...)
	}
	return output, nil
}

func decodeVarint(data []byte, offset, limit int) (uint64, int, error) {
	if offset < 0 || limit > len(data) || offset >= limit {
		return 0, 0, fmt.Errorf("varint starts outside input")
	}
	var value uint64
	for index := 0; index < 9; index++ {
		if offset+index >= limit {
			return 0, 0, fmt.Errorf("truncated varint")
		}
		current := data[offset+index]
		if index == 8 {
			return value<<8 | uint64(current), 9, nil
		}
		value = value<<7 | uint64(current&0x7f)
		if current&0x80 == 0 {
			return value, index + 1, nil
		}
	}
	return 0, 0, fmt.Errorf("invalid varint")
}

func decodeRecord(data []byte, encoding uint32) ([]any, error) {
	headerSizeValue, used, err := decodeVarint(data, 0, len(data))
	if err != nil {
		return nil, err
	}
	headerSize := int(headerSizeValue)
	if headerSize < used || headerSize > len(data) {
		return nil, fmt.Errorf("record header size %d exceeds record", headerSize)
	}
	serials := make([]uint64, 0)
	position := used
	for position < headerSize {
		serial, count, err := decodeVarint(data, position, headerSize)
		if err != nil {
			return nil, err
		}
		serials = append(serials, serial)
		position += count
	}
	body := headerSize
	values := make([]any, 0, len(serials))
	for _, serial := range serials {
		size, err := serialSize(serial)
		if err != nil {
			return nil, err
		}
		if body+size > len(data) {
			return nil, fmt.Errorf("serial type %d exceeds record body", serial)
		}
		field := data[body : body+size]
		body += size
		var value any
		switch {
		case serial == 0:
			value = nil
		case serial >= 1 && serial <= 6:
			value = signedBigEndian(field)
		case serial == 7:
			value = math.Float64frombits(binary.BigEndian.Uint64(field))
		case serial == 8:
			value = int64(0)
		case serial == 9:
			value = int64(1)
		case serial >= 12 && serial%2 == 0:
			value = append([]byte(nil), field...)
		case serial >= 13 && serial%2 == 1:
			text, err := decodeText(field, encoding)
			if err != nil {
				return nil, err
			}
			value = text
		default:
			return nil, fmt.Errorf("reserved serial type %d", serial)
		}
		values = append(values, value)
	}
	return values, nil
}

func serialSize(serial uint64) (int, error) {
	switch serial {
	case 0, 8, 9:
		return 0, nil
	case 1:
		return 1, nil
	case 2:
		return 2, nil
	case 3:
		return 3, nil
	case 4:
		return 4, nil
	case 5:
		return 6, nil
	case 6, 7:
		return 8, nil
	case 10, 11:
		return 0, fmt.Errorf("reserved serial type %d", serial)
	default:
		if serial >= 12 {
			size := (serial - 12) / 2
			if size > 1<<30 {
				return 0, fmt.Errorf("serial type %d exceeds field size limit", serial)
			}
			return int(size), nil
		}
	}
	return 0, fmt.Errorf("unsupported serial type %d", serial)
}

func signedBigEndian(data []byte) int64 {
	var value uint64
	for _, current := range data {
		value = value<<8 | uint64(current)
	}
	bits := uint(len(data) * 8)
	if bits < 64 && value&(uint64(1)<<(bits-1)) != 0 {
		value |= ^uint64(0) << bits
	}
	return int64(value)
}

func decodeText(data []byte, encoding uint32) (string, error) {
	switch encoding {
	case 1:
		return string(data), nil
	case 2, 3:
		if len(data)%2 != 0 {
			return "", fmt.Errorf("SQLite UTF-16 text has odd byte length")
		}
		units := make([]uint16, len(data)/2)
		var order binary.ByteOrder = binary.LittleEndian
		if encoding == 3 {
			order = binary.BigEndian
		}
		for index := range units {
			units[index] = order.Uint16(data[index*2 : index*2+2])
		}
		return string(utf16Decode(units)), nil
	default:
		return "", fmt.Errorf("unsupported SQLite text encoding %d", encoding)
	}
}

// utf16Decode is kept local to avoid exposing an encoding dependency through
// the database API.
func utf16Decode(values []uint16) []rune {
	output := make([]rune, 0, len(values))
	for index := 0; index < len(values); index++ {
		value := values[index]
		if value >= 0xd800 && value <= 0xdbff && index+1 < len(values) {
			next := values[index+1]
			if next >= 0xdc00 && next <= 0xdfff {
				output = append(output, rune(0x10000+(uint32(value-0xd800)<<10)+uint32(next-0xdc00)))
				index++
				continue
			}
		}
		output = append(output, rune(value))
	}
	return output
}

func sqliteUint32(value any) (uint32, bool) {
	switch value := value.(type) {
	case int64:
		if value >= 0 && value <= math.MaxUint32 {
			return uint32(value), true
		}
	case nil:
		return 0, true
	}
	return 0, false
}

func parseWAL(source storage.Reader, pageSize int) ([]walFrame, uint32, error) {
	if source.Size() < 32 {
		return nil, 0, fmt.Errorf("sqlite: WAL header is truncated")
	}
	header := make([]byte, 32)
	if _, err := readFullAt(source, header, 0); err != nil {
		return nil, 0, fmt.Errorf("sqlite: WAL header: %w", err)
	}
	magic := binary.BigEndian.Uint32(header[:4])
	var checksumOrder binary.ByteOrder
	switch magic {
	case 0x377f0682:
		checksumOrder = binary.LittleEndian
	case 0x377f0683:
		checksumOrder = binary.BigEndian
	default:
		return nil, 0, fmt.Errorf("sqlite: invalid WAL signature %#x", magic)
	}
	if version := binary.BigEndian.Uint32(header[4:8]); version != 3007000 {
		return nil, 0, fmt.Errorf("sqlite: unsupported WAL version %d", version)
	}
	if walPageSize := int(binary.BigEndian.Uint32(header[8:12])); walPageSize != pageSize {
		return nil, 0, fmt.Errorf("sqlite: WAL page size %d differs from database %d", walPageSize, pageSize)
	}
	s0, s1 := walChecksum(header[:24], checksumOrder, 0, 0)
	if s0 != binary.BigEndian.Uint32(header[24:28]) || s1 != binary.BigEndian.Uint32(header[28:32]) {
		return nil, 0, fmt.Errorf("sqlite: WAL header checksum mismatch")
	}
	salt1 := binary.BigEndian.Uint32(header[16:20])
	salt2 := binary.BigEndian.Uint32(header[20:24])
	frameSize := int64(24 + pageSize)
	frameCount := int((source.Size() - 32) / frameSize)
	frames := make([]walFrame, 0, frameCount)
	lastCommit := -1
	committedPages := uint32(0)
	for index := 0; index < frameCount; index++ {
		frame := make([]byte, 24+pageSize)
		if _, err := readFullAt(source, frame, 32+int64(index)*frameSize); err != nil {
			return nil, 0, fmt.Errorf("sqlite: WAL frame %d: %w", index, err)
		}
		if binary.BigEndian.Uint32(frame[8:12]) != salt1 || binary.BigEndian.Uint32(frame[12:16]) != salt2 {
			// WAL files are reusable. Bytes after the current valid frame run can
			// belong to an older transaction sequence with different salts.
			break
		}
		next0, next1 := walChecksum(frame[:8], checksumOrder, s0, s1)
		next0, next1 = walChecksum(frame[24:], checksumOrder, next0, next1)
		if next0 != binary.BigEndian.Uint32(frame[16:20]) || next1 != binary.BigEndian.Uint32(frame[20:24]) {
			// A torn or partially replaced trailing frame is not part of the
			// recovered WAL. Preserve the last complete commit before it.
			break
		}
		s0, s1 = next0, next1
		pageNumber := binary.BigEndian.Uint32(frame[:4])
		if pageNumber == 0 || pageNumber > maximumPages {
			return nil, 0, fmt.Errorf("sqlite: WAL frame %d has invalid page %d", index, pageNumber)
		}
		frames = append(frames, walFrame{pageNumber: pageNumber, data: append([]byte(nil), frame[24:]...)})
		if pages := binary.BigEndian.Uint32(frame[4:8]); pages != 0 {
			lastCommit = index
			committedPages = pages
		}
	}
	if lastCommit < 0 {
		return nil, 0, nil
	}
	return frames[:lastCommit+1], committedPages, nil
}

func walChecksum(data []byte, order binary.ByteOrder, s0, s1 uint32) (uint32, uint32) {
	for offset := 0; offset+8 <= len(data); offset += 8 {
		s0 += order.Uint32(data[offset:offset+4]) + s1
		s1 += order.Uint32(data[offset+4:offset+8]) + s0
	}
	return s0, s1
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
			return total, io.ErrUnexpectedEOF
		}
	}
	return total, nil
}
