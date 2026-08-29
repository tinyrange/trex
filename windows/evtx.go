package windows

import (
	"encoding/binary"
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"math"
	"strings"
	"unicode/utf16"

	"go.starlark.net/starlark"
)

const (
	evtxFileHeaderSize = 0x1000
	evtxChunkSize      = 0x10000
	evtxRecordStart    = 0x200
	evtxMaxValues      = 1 << 16
)

type evtxRecord struct {
	number     uint64
	timestamp  uint64
	templateID string
	values     []evtxValue
}

type evtxValue struct {
	typ   byte
	value any
}

func evtxRecordsValue(data []byte) (starlark.Value, error) {
	records, err := parseEVTX(data)
	if err != nil {
		return nil, fmt.Errorf("event_log: %w", err)
	}
	output := make([]starlark.Value, 0, len(records))
	for _, record := range records {
		values := make([]starlark.Value, len(record.values))
		for index, value := range record.values {
			values[index] = evtxStarlarkValue(value)
		}
		fields := starlark.StringDict{
			"record_number": starlark.MakeUint64(record.number),
			"time":          starlark.MakeUint64(record.timestamp),
			"template_id":   starlark.String(record.templateID),
			"values":        starlark.NewList(values),
		}
		// The standard Windows event schema stores EventID in substitution 3.
		if len(record.values) > 3 {
			if eventID, ok := evtxUnsigned(record.values[3].value); ok {
				fields["event_id"] = starlark.MakeUint64(eventID)
			}
		}
		output = append(output, starfile.NewRecord(fields))
	}
	return starlark.NewList(output), nil
}

func parseEVTX(data []byte) ([]evtxRecord, error) {
	if len(data) < evtxFileHeaderSize || string(data[:8]) != "ElfFile\x00" {
		return nil, fmt.Errorf("invalid EVTX file header")
	}
	var records []evtxRecord
	for chunkOffset := evtxFileHeaderSize; chunkOffset+evtxRecordStart <= len(data); chunkOffset += evtxChunkSize {
		chunkEnd := min(chunkOffset+evtxChunkSize, len(data))
		chunk := data[chunkOffset:chunkEnd]
		if len(chunk) < evtxRecordStart || string(chunk[:8]) != "ElfChnk\x00" {
			continue
		}
		free := int(binary.LittleEndian.Uint32(chunk[48:52]))
		if free < evtxRecordStart || free > len(chunk) {
			return nil, fmt.Errorf("EVTX chunk at %#x has invalid free-space offset %#x", chunkOffset, free)
		}
		for offset := evtxRecordStart; offset+28 <= free; {
			if binary.LittleEndian.Uint32(chunk[offset:offset+4]) != 0x00002a2a {
				break
			}
			size := int(binary.LittleEndian.Uint32(chunk[offset+4 : offset+8]))
			if size < 28 || offset+size > free || binary.LittleEndian.Uint32(chunk[offset+size-4:offset+size]) != uint32(size) {
				return nil, fmt.Errorf("EVTX chunk at %#x has invalid record at %#x", chunkOffset, offset)
			}
			values, templateID, err := decodeEVTXTemplateInstance(chunk, offset+24, offset+size-4, 0)
			if err != nil {
				return nil, fmt.Errorf("EVTX record %d: %w", binary.LittleEndian.Uint64(chunk[offset+8:offset+16]), err)
			}
			records = append(records, evtxRecord{
				number:     binary.LittleEndian.Uint64(chunk[offset+8 : offset+16]),
				timestamp:  binary.LittleEndian.Uint64(chunk[offset+16 : offset+24]),
				templateID: templateID,
				values:     values,
			})
			offset += size
		}
	}
	return records, nil
}

func decodeEVTXTemplateInstance(chunk []byte, start, end, depth int) ([]evtxValue, string, error) {
	if depth > 16 {
		return nil, "", fmt.Errorf("BinXML template nesting exceeds 16 levels")
	}
	if start < 0 || end > len(chunk) || start+14 > end || chunk[start] != 0x0f || chunk[start+1] != 1 || chunk[start+4] != 0x0c {
		return nil, "", fmt.Errorf("invalid BinXML template instance at %#x", start)
	}
	templateOffset := int(binary.LittleEndian.Uint32(chunk[start+10 : start+14]))
	valuesOffset := start + 14
	templateID := ""
	if templateOffset > 0 && templateOffset+24 <= len(chunk) {
		templateID = formatPDBGUID(chunk[templateOffset+4 : templateOffset+20])
		templateLength := int(binary.LittleEndian.Uint32(chunk[templateOffset+20 : templateOffset+24]))
		if templateLength < 0 || templateOffset+24+templateLength > len(chunk) {
			return nil, "", fmt.Errorf("invalid BinXML template definition at %#x", templateOffset)
		}
		if templateOffset >= start && templateOffset < end {
			valuesOffset = templateOffset + 24 + templateLength
		}
	}
	if valuesOffset+4 > end {
		return nil, "", fmt.Errorf("missing BinXML value specification")
	}
	count := int(binary.LittleEndian.Uint32(chunk[valuesOffset : valuesOffset+4]))
	if count < 0 || count > evtxMaxValues || valuesOffset+4+count*4 > end {
		return nil, "", fmt.Errorf("invalid BinXML value count %d", count)
	}
	dataOffset := valuesOffset + 4 + count*4
	values := make([]evtxValue, 0, count)
	for index := 0; index < count; index++ {
		spec := valuesOffset + 4 + index*4
		length := int(binary.LittleEndian.Uint16(chunk[spec : spec+2]))
		typ := chunk[spec+2]
		if dataOffset+length > end {
			return nil, "", fmt.Errorf("BinXML value %d exceeds its record", index)
		}
		value, err := decodeEVTXValue(chunk, dataOffset, length, typ, depth)
		if err != nil {
			return nil, "", fmt.Errorf("BinXML value %d: %w", index, err)
		}
		values = append(values, evtxValue{typ: typ, value: value})
		dataOffset += length
	}
	return values, templateID, nil
}

func decodeEVTXValue(chunk []byte, offset, length int, typ byte, depth int) (any, error) {
	raw := chunk[offset : offset+length]
	switch typ {
	case 0x00:
		return nil, nil
	case 0x01:
		return decodeEVTXUTF16(raw), nil
	case 0x02:
		return strings.TrimRight(string(raw), "\x00"), nil
	case 0x03:
		if length != 1 {
			return nil, fmt.Errorf("Int8 has length %d", length)
		}
		return int64(int8(raw[0])), nil
	case 0x04:
		if length != 1 {
			return nil, fmt.Errorf("UInt8 has length %d", length)
		}
		return uint64(raw[0]), nil
	case 0x05:
		if length != 2 {
			return nil, fmt.Errorf("Int16 has length %d", length)
		}
		return int64(int16(binary.LittleEndian.Uint16(raw))), nil
	case 0x06:
		if length != 2 {
			return nil, fmt.Errorf("UInt16 has length %d", length)
		}
		return uint64(binary.LittleEndian.Uint16(raw)), nil
	case 0x07:
		if length != 4 {
			return nil, fmt.Errorf("Int32 has length %d", length)
		}
		return int64(int32(binary.LittleEndian.Uint32(raw))), nil
	case 0x08, 0x14:
		if length != 4 {
			return nil, fmt.Errorf("UInt32 has length %d", length)
		}
		return uint64(binary.LittleEndian.Uint32(raw)), nil
	case 0x09:
		if length != 8 {
			return nil, fmt.Errorf("Int64 has length %d", length)
		}
		return int64(binary.LittleEndian.Uint64(raw)), nil
	case 0x0a, 0x10, 0x11, 0x15:
		if length != 8 && !(typ == 0x10 && length == 4) {
			return nil, fmt.Errorf("64-bit value has length %d", length)
		}
		if length == 4 {
			return uint64(binary.LittleEndian.Uint32(raw)), nil
		}
		return binary.LittleEndian.Uint64(raw), nil
	case 0x0b:
		if length != 4 {
			return nil, fmt.Errorf("Real32 has length %d", length)
		}
		return float64(math.Float32frombits(binary.LittleEndian.Uint32(raw))), nil
	case 0x0c:
		if length != 8 {
			return nil, fmt.Errorf("Real64 has length %d", length)
		}
		return math.Float64frombits(binary.LittleEndian.Uint64(raw)), nil
	case 0x0d:
		if length != 1 || raw[0] > 1 {
			return nil, fmt.Errorf("invalid Bool value")
		}
		return raw[0] != 0, nil
	case 0x0f:
		if length != 16 {
			return nil, fmt.Errorf("GUID has length %d", length)
		}
		return formatPDBGUID(raw), nil
	case 0x13:
		return evtxSID(raw)
	case 0x21:
		if length >= 5 && raw[0] == 0x0f && raw[4] == 0x0c {
			values, _, err := decodeEVTXTemplateInstance(chunk, offset, offset+length, depth+1)
			if err == nil {
				return values, nil
			}
		}
		// BinXML values may also contain a direct element fragment. Preserve
		// those losslessly until XML rendering is requested by a higher layer.
		return append([]byte(nil), raw...), nil
	default:
		return append([]byte(nil), raw...), nil
	}
}

func decodeEVTXUTF16(raw []byte) string {
	units := make([]uint16, 0, len(raw)/2)
	for offset := 0; offset+2 <= len(raw); offset += 2 {
		unit := binary.LittleEndian.Uint16(raw[offset : offset+2])
		if unit == 0 {
			break
		}
		units = append(units, unit)
	}
	return string(utf16.Decode(units))
}

func evtxSID(raw []byte) (string, error) {
	if len(raw) < 8 || raw[0] != 1 || int(raw[1]) > 15 || len(raw) != 8+int(raw[1])*4 {
		return "", fmt.Errorf("invalid SID")
	}
	authority := uint64(0)
	for _, value := range raw[2:8] {
		authority = authority<<8 | uint64(value)
	}
	parts := []string{fmt.Sprintf("S-1-%d", authority)}
	for index := 0; index < int(raw[1]); index++ {
		parts = append(parts, fmt.Sprint(binary.LittleEndian.Uint32(raw[8+index*4:12+index*4])))
	}
	return strings.Join(parts, "-"), nil
}

func evtxUnsigned(value any) (uint64, bool) {
	switch value := value.(type) {
	case uint64:
		return value, true
	case int64:
		return uint64(value), value >= 0
	default:
		return 0, false
	}
}

func evtxStarlarkValue(value evtxValue) starlark.Value {
	switch item := value.value.(type) {
	case nil:
		return starlark.None
	case string:
		return starlark.String(item)
	case []byte:
		return starlark.Bytes(item)
	case uint64:
		return starlark.MakeUint64(item)
	case int64:
		return starlark.MakeInt64(item)
	case float64:
		return starlark.Float(item)
	case bool:
		return starlark.Bool(item)
	case []evtxValue:
		values := make([]starlark.Value, len(item))
		for index, nested := range item {
			values[index] = evtxStarlarkValue(nested)
		}
		return starlark.NewList(values)
	default:
		return starlark.String(fmt.Sprint(item))
	}
}
