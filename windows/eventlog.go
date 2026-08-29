package windows

import (
	"encoding/binary"
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"io"
	"unicode/utf16"

	"go.starlark.net/starlark"
)

const defaultEventLogSize = 0x500000

func eventLogBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("event_log", args, kwargs, "file", &value); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("event_log: got %s, want file", value.Type())
	}
	data, err := starfile.ReadAll(file)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("event_log: %w", err)
	}
	if len(data) >= 8 && string(data[:8]) == "ElfFile\x00" {
		return evtxRecordsValue(data)
	}
	records, err := parseEventLog(data)
	if err != nil {
		return nil, fmt.Errorf("event_log: %w", err)
	}
	values := make([]starlark.Value, 0, len(records))
	for _, record := range records {
		item := starlark.NewDict(8)
		stringsValue := make([]starlark.Value, len(record.strings))
		for index, value := range record.strings {
			stringsValue[index] = starlark.String(value)
		}
		fields := map[string]starlark.Value{
			"computer":      starlark.String(record.computer),
			"data":          starlark.Bytes(record.data),
			"event_id":      starlark.MakeUint64(uint64(record.eventID)),
			"record_number": starlark.MakeUint64(uint64(record.number)),
			"source":        starlark.String(record.source),
			"strings":       starlark.NewList(stringsValue),
			"time":          starlark.MakeUint64(uint64(record.timestamp)),
			"type":          starlark.MakeUint64(uint64(record.eventType)),
		}
		for name, value := range fields {
			if err := item.SetKey(starlark.String(name), value); err != nil {
				return nil, err
			}
		}
		values = append(values, item)
	}
	return starlark.NewList(values), nil
}

type eventLogRecord struct {
	number    uint32
	timestamp uint32
	eventID   uint32
	eventType uint16
	source    string
	computer  string
	strings   []string
	data      []byte
}

func parseEventLog(data []byte) ([]eventLogRecord, error) {
	if len(data) < 0x30 || binary.LittleEndian.Uint32(data[0:4]) != 0x30 || string(data[4:8]) != "LfLe" {
		return nil, fmt.Errorf("invalid event log header")
	}
	start := int(binary.LittleEndian.Uint32(data[0x10:0x14]))
	end := int(binary.LittleEndian.Uint32(data[0x14:0x18]))
	if start < 0x30 || start > len(data) || end < 0x30 || end > len(data) {
		return nil, fmt.Errorf("event log offsets are outside the file")
	}
	dirty := start == end
	var records []eventLogRecord
	offset := start
	for visited := 0; visited < len(data); {
		if !dirty && offset == end {
			break
		}
		if offset+8 > len(data) {
			offset = 0x30
			continue
		}
		if binary.LittleEndian.Uint32(data[offset+4:offset+8]) == 0x11111111 {
			break
		}
		length := int(binary.LittleEndian.Uint32(data[offset : offset+4]))
		if length < 0x38 || offset+length > len(data) || string(data[offset+4:offset+8]) != "LfLe" {
			return nil, fmt.Errorf("invalid record at %#x", offset)
		}
		record, err := parseEventLogRecord(data[offset : offset+length])
		if err != nil {
			return nil, fmt.Errorf("record at %#x: %w", offset, err)
		}
		records = append(records, record)
		offset += length
		visited += length
		if offset == len(data) {
			offset = 0x30
		}
	}
	return records, nil
}

func parseEventLogRecord(data []byte) (eventLogRecord, error) {
	stringCount := int(binary.LittleEndian.Uint16(data[0x1a:0x1c]))
	stringOffset := int(binary.LittleEndian.Uint32(data[0x24:0x28]))
	dataLength := int(binary.LittleEndian.Uint32(data[0x30:0x34]))
	dataOffset := int(binary.LittleEndian.Uint32(data[0x34:0x38]))
	if stringOffset < 0x38 || stringOffset > len(data) || dataLength < 0 || dataOffset < 0 || dataOffset+dataLength > len(data) {
		return eventLogRecord{}, fmt.Errorf("invalid payload offsets")
	}
	source, next, err := eventLogUTF16Z(data, 0x38)
	if err != nil {
		return eventLogRecord{}, err
	}
	computer, _, err := eventLogUTF16Z(data, next)
	if err != nil {
		return eventLogRecord{}, err
	}
	stringsValue := make([]string, 0, stringCount)
	cursor := stringOffset
	for index := 0; index < stringCount; index++ {
		value, next, err := eventLogUTF16Z(data, cursor)
		if err != nil {
			return eventLogRecord{}, fmt.Errorf("string %d: %w", index, err)
		}
		stringsValue = append(stringsValue, value)
		cursor = next
	}
	return eventLogRecord{
		number:    binary.LittleEndian.Uint32(data[0x08:0x0c]),
		timestamp: binary.LittleEndian.Uint32(data[0x0c:0x10]),
		eventID:   binary.LittleEndian.Uint32(data[0x14:0x18]),
		eventType: binary.LittleEndian.Uint16(data[0x18:0x1a]),
		source:    source,
		computer:  computer,
		strings:   stringsValue,
		data:      append([]byte(nil), data[dataOffset:dataOffset+dataLength]...),
	}, nil
}

func eventLogUTF16Z(data []byte, offset int) (string, int, error) {
	if offset < 0 || offset >= len(data) || offset%2 != 0 {
		return "", 0, fmt.Errorf("invalid UTF-16 offset %#x", offset)
	}
	var units []uint16
	for cursor := offset; cursor+2 <= len(data); cursor += 2 {
		unit := binary.LittleEndian.Uint16(data[cursor : cursor+2])
		if unit == 0 {
			return string(utf16.Decode(units)), cursor + 2, nil
		}
		units = append(units, unit)
	}
	return "", 0, fmt.Errorf("unterminated UTF-16 string")
}

func emptyEventLogBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	size := defaultEventLogSize
	if err := starlark.UnpackArgs("empty_event_log", args, kwargs, "size?", &size); err != nil {
		return nil, err
	}
	if size < 0x58 {
		return nil, fmt.Errorf("empty_event_log: size must be at least 0x58")
	}
	data := make([]byte, size)
	writeEventLogHeader(data, uint32(size))
	return &starfile.Bytes{Name: "empty.evt", Data: data}, nil
}

func writeEventLogHeader(data []byte, maxSize uint32) {
	binary.LittleEndian.PutUint32(data[0x00:0x04], 0x30)
	copy(data[0x04:0x08], []byte("LfLe"))
	binary.LittleEndian.PutUint32(data[0x08:0x0c], 1)
	binary.LittleEndian.PutUint32(data[0x0c:0x10], 1)
	binary.LittleEndian.PutUint32(data[0x10:0x14], 0x30)
	binary.LittleEndian.PutUint32(data[0x14:0x18], 0x30)
	binary.LittleEndian.PutUint32(data[0x18:0x1c], 1)
	binary.LittleEndian.PutUint32(data[0x20:0x24], maxSize)
	binary.LittleEndian.PutUint32(data[0x28:0x2c], 0x00093a80)
	binary.LittleEndian.PutUint32(data[0x2c:0x30], 0x30)

	binary.LittleEndian.PutUint32(data[0x30:0x34], 0x28)
	binary.LittleEndian.PutUint32(data[0x34:0x38], 0x11111111)
	binary.LittleEndian.PutUint32(data[0x38:0x3c], 0x22222222)
	binary.LittleEndian.PutUint32(data[0x3c:0x40], 0x33333333)
	binary.LittleEndian.PutUint32(data[0x40:0x44], 0x44444444)
	binary.LittleEndian.PutUint32(data[0x44:0x48], 0x30)
	binary.LittleEndian.PutUint32(data[0x48:0x4c], 0x30)
	binary.LittleEndian.PutUint32(data[0x4c:0x50], 1)
	binary.LittleEndian.PutUint32(data[0x54:0x58], 0x28)
}
