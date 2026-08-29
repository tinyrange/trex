package ese

import (
	"encoding/binary"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
	"unicode/utf16"
)

const (
	ColumnBoolean       = 1
	ColumnUnsignedByte  = 2
	ColumnSignedShort   = 3
	ColumnSignedLong    = 4
	ColumnCurrency      = 5
	ColumnSingle        = 6
	ColumnDouble        = 7
	ColumnDateTime      = 8
	ColumnBinary        = 9
	ColumnText          = 10
	ColumnLongBinary    = 11
	ColumnLongText      = 12
	ColumnUnsignedLong  = 14
	ColumnLongLong      = 15
	ColumnGUID          = 16
	ColumnUnsignedShort = 17
)

// ColumnDefinition describes a persisted ESE column. Identifiers 1-127 are
// fixed, 128-255 are variable, and identifiers at or above 256 are tagged.
type ColumnDefinition struct {
	CodePage   uint32
	Flags      uint32
	Identifier uint32
	Maximum    uint32
	Name       string
	Type       uint32
}

// Row contains logical column values keyed by exact column name.
type Row map[string]any

func encodeRecord(columns []ColumnDefinition, row Row) ([]byte, error) {
	ordered := append([]ColumnDefinition(nil), columns...)
	sort.SliceStable(ordered, func(left, right int) bool {
		return ordered[left].Identifier < ordered[right].Identifier
	})
	lastFixed, lastVariable := uint32(0), uint32(127)
	for _, column := range ordered {
		switch {
		case column.Identifier == 0:
			return nil, fmt.Errorf("ese: column %q has zero identifier", column.Name)
		case column.Identifier < 128:
			if value, present := row[column.Name]; present && value != nil {
				lastFixed = max(lastFixed, column.Identifier)
			}
		case column.Identifier < 256:
			lastVariable = max(lastVariable, column.Identifier)
		}
	}

	fixed := make([]byte, 0, 128)
	fixedNulls := make([]byte, (lastFixed+7)/8)
	for identifier := uint32(1); identifier <= lastFixed; identifier++ {
		column, present := columnByIdentifier(ordered, identifier)
		if !present {
			return nil, fmt.Errorf("ese: fixed column identifier %d is undefined", identifier)
		}
		value, present := row[column.Name]
		if !present || value == nil {
			fixed = append(fixed, make([]byte, fixedColumnSize(column.Type))...)
			fixedNulls[(identifier-1)/8] |= 1 << ((identifier - 1) % 8)
			continue
		}
		raw, err := encodeColumn(column, value)
		if err != nil {
			return nil, err
		}
		if len(raw) != fixedColumnSize(column.Type) {
			return nil, fmt.Errorf("ese: fixed column %q encoded to %d bytes", column.Name, len(raw))
		}
		fixed = append(fixed, raw...)
	}

	variableCount := int(lastVariable - 127)
	variableEnds := make([]uint16, variableCount)
	variable := make([]byte, 0, 256)
	for index := 0; index < variableCount; index++ {
		identifier := uint32(128 + index)
		column, defined := columnByIdentifier(ordered, identifier)
		value, present := row[column.Name]
		if !defined || !present || value == nil {
			variableEnds[index] = uint16(len(variable)) | 0x8000
			continue
		}
		raw, err := encodeColumn(column, value)
		if err != nil {
			return nil, err
		}
		if len(variable)+len(raw) > 0x7fff {
			return nil, fmt.Errorf("ese: variable data exceeds 32767 bytes")
		}
		variable = append(variable, raw...)
		variableEnds[index] = uint16(len(variable))
	}

	type taggedField struct {
		identifier uint16
		data       []byte
	}
	taggedFields := make([]taggedField, 0)
	for _, column := range ordered {
		if column.Identifier < 256 || column.Identifier > 0xffff {
			continue
		}
		value, present := row[column.Name]
		if !present || value == nil {
			continue
		}
		raw, err := encodeColumn(column, value)
		if err != nil {
			return nil, err
		}
		taggedFields = append(taggedFields, taggedField{identifier: uint16(column.Identifier), data: raw})
	}
	taggedDirectorySize := len(taggedFields) * 4
	tagged := make([]byte, taggedDirectorySize)
	for index, field := range taggedFields {
		start := len(tagged)
		if start > 0x7fff {
			return nil, fmt.Errorf("ese: tagged data exceeds 32767 bytes")
		}
		binary.LittleEndian.PutUint16(tagged[index*4:index*4+2], field.identifier)
		binary.LittleEndian.PutUint16(tagged[index*4+2:index*4+4], uint16(start))
		// Large-page tagged values carry one explicit flag byte. Bit zero means
		// the value is stored intrinsically in this record.
		tagged = append(tagged, 0x01)
		tagged = append(tagged, field.data...)
	}

	variableOffset := 4 + len(fixed) + len(fixedNulls)
	if variableOffset > 0xffff {
		return nil, fmt.Errorf("ese: fixed data exceeds 65535 bytes")
	}
	record := make([]byte, variableOffset+variableCount*2)
	record[0] = byte(lastFixed)
	record[1] = byte(lastVariable)
	binary.LittleEndian.PutUint16(record[2:4], uint16(variableOffset))
	copy(record[4:], fixed)
	copy(record[4+len(fixed):], fixedNulls)
	for index, end := range variableEnds {
		binary.LittleEndian.PutUint16(record[variableOffset+index*2:variableOffset+index*2+2], end)
	}
	record = append(record, variable...)
	record = append(record, tagged...)
	return record, nil
}

func columnByIdentifier(columns []ColumnDefinition, identifier uint32) (ColumnDefinition, bool) {
	for _, column := range columns {
		if column.Identifier == identifier {
			return column, true
		}
	}
	return ColumnDefinition{}, false
}

func fixedColumnSize(columnType uint32) int {
	switch columnType {
	case ColumnBoolean, ColumnUnsignedByte:
		return 1
	case ColumnSignedShort, ColumnUnsignedShort:
		return 2
	case ColumnSignedLong, ColumnUnsignedLong, ColumnSingle:
		return 4
	case ColumnCurrency, ColumnDouble, ColumnDateTime, ColumnLongLong:
		return 8
	case ColumnGUID:
		return 16
	default:
		return 0
	}
}

func encodeColumn(column ColumnDefinition, value any) ([]byte, error) {
	size := fixedColumnSize(column.Type)
	if size > 0 {
		data := make([]byte, size)
		switch column.Type {
		case ColumnBoolean:
			boolean, ok := value.(bool)
			if !ok {
				return nil, columnValueError(column, value)
			}
			if boolean {
				data[0] = 0xff
			}
		case ColumnUnsignedByte:
			integer, ok := unsignedValue(value, 8)
			if !ok {
				return nil, columnValueError(column, value)
			}
			data[0] = byte(integer)
		case ColumnSignedShort:
			integer, ok := signedValue(value, 16)
			if !ok {
				return nil, columnValueError(column, value)
			}
			binary.LittleEndian.PutUint16(data, uint16(integer))
		case ColumnUnsignedShort:
			integer, ok := unsignedValue(value, 16)
			if !ok {
				return nil, columnValueError(column, value)
			}
			binary.LittleEndian.PutUint16(data, uint16(integer))
		case ColumnSignedLong:
			integer, ok := signedValue(value, 32)
			if !ok {
				return nil, columnValueError(column, value)
			}
			binary.LittleEndian.PutUint32(data, uint32(integer))
		case ColumnUnsignedLong:
			integer, ok := unsignedValue(value, 32)
			if !ok {
				return nil, columnValueError(column, value)
			}
			binary.LittleEndian.PutUint32(data, uint32(integer))
		case ColumnCurrency, ColumnLongLong:
			integer, ok := signedValue(value, 64)
			if !ok {
				return nil, columnValueError(column, value)
			}
			binary.LittleEndian.PutUint64(data, uint64(integer))
		case ColumnSingle:
			floating, ok := floatValue(value)
			if !ok {
				return nil, columnValueError(column, value)
			}
			binary.LittleEndian.PutUint32(data, math.Float32bits(float32(floating)))
		case ColumnDouble:
			floating, ok := floatValue(value)
			if !ok {
				return nil, columnValueError(column, value)
			}
			binary.LittleEndian.PutUint64(data, math.Float64bits(floating))
		case ColumnDateTime:
			switch typed := value.(type) {
			case time.Time:
				const epoch = 116444736000000000
				binary.LittleEndian.PutUint64(data, uint64(typed.UTC().UnixNano()/100)+epoch)
			default:
				floating, ok := floatValue(value)
				if !ok {
					return nil, columnValueError(column, value)
				}
				binary.LittleEndian.PutUint64(data, math.Float64bits(floating))
			}
		case ColumnGUID:
			raw, ok := value.([]byte)
			if !ok || len(raw) != 16 {
				return nil, columnValueError(column, value)
			}
			copy(data, raw)
		}
		return data, nil
	}

	switch column.Type {
	case ColumnBinary, ColumnLongBinary:
		raw, ok := value.([]byte)
		if !ok {
			return nil, columnValueError(column, value)
		}
		return append([]byte(nil), raw...), nil
	case ColumnText, ColumnLongText:
		text, ok := value.(string)
		if !ok {
			return nil, columnValueError(column, value)
		}
		if column.CodePage != 1200 {
			return []byte(text), nil
		}
		words := utf16.Encode([]rune(text))
		data := make([]byte, len(words)*2)
		for index, word := range words {
			binary.LittleEndian.PutUint16(data[index*2:index*2+2], word)
		}
		return data, nil
	default:
		return nil, fmt.Errorf("ese: column %q has unsupported type %d", column.Name, column.Type)
	}
}

func columnValueError(column ColumnDefinition, value any) error {
	return fmt.Errorf("ese: column %q cannot encode %T as %s", column.Name, value, columnTypeName(column.Type))
}

func signedValue(value any, width int) (int64, bool) {
	var result int64
	switch value := value.(type) {
	case int:
		result = int64(value)
	case int8:
		result = int64(value)
	case int16:
		result = int64(value)
	case int32:
		result = int64(value)
	case int64:
		result = value
	default:
		return 0, false
	}
	if width < 64 {
		minimum, maximum := -(int64(1) << (width - 1)), int64(1)<<(width-1)-1
		if result < minimum || result > maximum {
			return 0, false
		}
	}
	return result, true
}

func unsignedValue(value any, width int) (uint64, bool) {
	var result uint64
	switch value := value.(type) {
	case uint:
		result = uint64(value)
	case uint8:
		result = uint64(value)
	case uint16:
		result = uint64(value)
	case uint32:
		result = uint64(value)
	case uint64:
		result = value
	case int:
		if value < 0 {
			return 0, false
		}
		result = uint64(value)
	default:
		return 0, false
	}
	if width < 64 && result >= uint64(1)<<width {
		return 0, false
	}
	return result, true
}

func floatValue(value any) (float64, bool) {
	switch value := value.(type) {
	case float32:
		return float64(value), true
	case float64:
		return value, true
	default:
		return 0, false
	}
}

func normalizeFixed(column ColumnDefinition, raw []byte, descending bool) ([]byte, error) {
	if len(raw) != fixedColumnSize(column.Type) {
		return nil, fmt.Errorf("ese: invalid fixed key value for %q", column.Name)
	}
	segment := []byte{0x7f}
	switch column.Type {
	case ColumnBoolean:
		if raw[0] == 0 {
			segment = append(segment, 0)
		} else {
			segment = append(segment, 0xff)
		}
	case ColumnUnsignedByte:
		segment = append(segment, raw[0])
	case ColumnSignedShort:
		value := binary.LittleEndian.Uint16(raw) ^ 0x8000
		segment = binary.BigEndian.AppendUint16(segment, value)
	case ColumnUnsignedShort:
		segment = binary.BigEndian.AppendUint16(segment, binary.LittleEndian.Uint16(raw))
	case ColumnSignedLong:
		value := binary.LittleEndian.Uint32(raw) ^ 0x80000000
		segment = binary.BigEndian.AppendUint32(segment, value)
	case ColumnUnsignedLong:
		segment = binary.BigEndian.AppendUint32(segment, binary.LittleEndian.Uint32(raw))
	case ColumnCurrency, ColumnLongLong:
		value := binary.LittleEndian.Uint64(raw) ^ 0x8000000000000000
		segment = binary.BigEndian.AppendUint64(segment, value)
	case ColumnSingle:
		value := binary.LittleEndian.Uint32(raw)
		if value&0x80000000 != 0 {
			value = ^value
		} else {
			value ^= 0x80000000
		}
		segment = binary.BigEndian.AppendUint32(segment, value)
	case ColumnDouble, ColumnDateTime:
		value := binary.LittleEndian.Uint64(raw)
		if value&0x8000000000000000 != 0 {
			value = ^value
		} else {
			value ^= 0x8000000000000000
		}
		segment = binary.BigEndian.AppendUint64(segment, value)
	default:
		return nil, fmt.Errorf("ese: fixed key type %d is not supported", column.Type)
	}
	if descending {
		for index := range segment {
			segment[index] = ^segment[index]
		}
	}
	return segment, nil
}

func encodeIndexKey(columns []ColumnDefinition, row Row, identifiers []int32) ([]byte, error) {
	key := make([]byte, 0, len(identifiers)*9)
	for _, signedIdentifier := range identifiers {
		descending := signedIdentifier < 0
		identifier := uint32(signedIdentifier)
		if descending {
			identifier = uint32(-signedIdentifier)
		}
		column, present := columnByIdentifier(columns, identifier)
		if !present {
			return nil, fmt.Errorf("ese: index column %d is undefined", identifier)
		}
		value, present := row[column.Name]
		if !present || value == nil {
			if descending {
				key = append(key, 0xff)
			} else {
				key = append(key, 0x00)
			}
			continue
		}
		raw, err := encodeColumn(column, value)
		if err != nil {
			return nil, err
		}
		if fixedColumnSize(column.Type) == 0 {
			return nil, fmt.Errorf("ese: text and binary index normalization is not implemented for %q", column.Name)
		}
		segment, err := normalizeFixed(column, raw, descending)
		if err != nil {
			return nil, err
		}
		key = append(key, segment...)
	}
	return key, nil
}

func recordLeafEntry(key, record []byte) ([]byte, error) {
	if len(key) > 0x1fff {
		return nil, fmt.Errorf("ese: leaf key exceeds 8191 bytes")
	}
	entry := make([]byte, 2+len(key)+len(record))
	binary.LittleEndian.PutUint16(entry[:2], uint16(len(key)))
	copy(entry[2:], key)
	copy(entry[2+len(key):], record)
	return entry, nil
}

func branchEntry(key []byte, child uint32) ([]byte, error) {
	if len(key) > 0x1fff {
		return nil, fmt.Errorf("ese: branch key exceeds 8191 bytes")
	}
	entry := make([]byte, 2+len(key)+4)
	binary.LittleEndian.PutUint16(entry[:2], uint16(len(key)))
	copy(entry[2:], key)
	binary.LittleEndian.PutUint32(entry[2+len(key):], child)
	return entry, nil
}

type encodedPage struct {
	dbtime uint64
	flags  uint32
	next   uint32
	number uint32
	objid  uint32
	prev   uint32
	values [][]byte
}

func (spec encodedPage) encode(pageSize int) ([]byte, error) {
	headerSize := 40
	if pageSize > 8192 {
		headerSize = 80
	}
	if pageSize != 2048 && pageSize != 4096 && pageSize != 8192 && pageSize != 16384 && pageSize != 32768 {
		return nil, fmt.Errorf("ese: invalid page size %d", pageSize)
	}
	page := make([]byte, pageSize)
	binary.LittleEndian.PutUint64(page[8:16], spec.dbtime)
	binary.LittleEndian.PutUint32(page[16:20], spec.prev)
	binary.LittleEndian.PutUint32(page[20:24], spec.next)
	binary.LittleEndian.PutUint32(page[24:28], spec.objid)
	binary.LittleEndian.PutUint32(page[36:40], spec.flags)
	used := 0
	for index, value := range spec.values {
		if len(value) > 0x7fff {
			return nil, fmt.Errorf("ese: page %d tag %d exceeds 32767 bytes", spec.number, index)
		}
		descriptor := pageSize - 4*(index+1)
		if headerSize+used+len(value) > descriptor {
			return nil, fmt.Errorf("ese: page %d values exceed page capacity", spec.number)
		}
		copy(page[headerSize+used:], value)
		binary.LittleEndian.PutUint16(page[descriptor:descriptor+2], uint16(len(value)))
		binary.LittleEndian.PutUint16(page[descriptor+2:descriptor+4], uint16(used))
		used += len(value)
	}
	tagBytes := len(spec.values) * 4
	free := pageSize - headerSize - used - tagBytes
	if free < 0 || used > 0xffff || len(spec.values) > 0x0fff {
		return nil, fmt.Errorf("ese: page %d layout exceeds persisted fields", spec.number)
	}
	binary.LittleEndian.PutUint16(page[28:30], uint16(free))
	binary.LittleEndian.PutUint16(page[32:34], uint16(used))
	binary.LittleEndian.PutUint16(page[34:36], uint16(len(spec.values)))
	if err := setPageChecksum(page, spec.number); err != nil {
		return nil, err
	}
	return page, nil
}

func validateColumns(columns []ColumnDefinition) error {
	identifiers := make(map[uint32]bool)
	names := make(map[string]bool)
	for _, column := range columns {
		if column.Identifier == 0 || column.Identifier > 0xffff {
			return fmt.Errorf("ese: column %q has invalid identifier %d", column.Name, column.Identifier)
		}
		if identifiers[column.Identifier] {
			return fmt.Errorf("ese: duplicate column identifier %d", column.Identifier)
		}
		identifiers[column.Identifier] = true
		name := strings.ToLower(column.Name)
		if name == "" || names[name] {
			return fmt.Errorf("ese: duplicate or empty column name %q", column.Name)
		}
		names[name] = true
		if column.Type == 0 || column.Type > ColumnUnsignedShort || fixedColumnSize(column.Type) == 0 && column.Type != ColumnBinary && column.Type != ColumnText && column.Type != ColumnLongBinary && column.Type != ColumnLongText {
			return fmt.Errorf("ese: column %q has unsupported type %d", column.Name, column.Type)
		}
	}
	return nil
}
