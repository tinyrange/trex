// Package registry provides portable, read-only access to Windows REGF hives.
package registry

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"unicode/utf16"

	"github.com/tinyrange/trex/storage"
)

const (
	baseBlockSize   = int64(4096)
	maximumCellSize = int64(256 << 20)
	maximumSubkeys  = 1 << 20
)

type Hive struct {
	file     storage.Reader
	rootCell uint32
}

type Value struct {
	Name string
	Type uint32
	Data []byte
}

type NamedValue struct {
	Key   string
	Value Value
	Found bool
}

type key struct {
	name       string
	cell       uint32
	subkeyList uint32
	subkeys    uint32
	valueList  uint32
	values     uint32
}

func Open(file storage.Reader) (*Hive, error) {
	if file == nil || file.Size() < baseBlockSize {
		return nil, fmt.Errorf("registry hive: file is smaller than one base block")
	}
	header := make([]byte, baseBlockSize)
	if _, err := file.ReadAt(header, 0); err != nil {
		return nil, fmt.Errorf("registry hive: read base block: %w", err)
	}
	if string(header[:4]) != "regf" {
		return nil, fmt.Errorf("registry hive: invalid regf signature")
	}
	return &Hive{file: file, rootCell: binary.LittleEndian.Uint32(header[0x24:0x28])}, nil
}

func (h *Hive) Subkeys(path string) ([]string, error) {
	parent, err := h.lookup(path)
	if err != nil {
		return nil, err
	}
	children, err := h.readSubkeys(parent)
	if err != nil {
		return nil, err
	}
	result := make([]string, len(children))
	for index, child := range children {
		result[index] = child.name
	}
	return result, nil
}

func (h *Hive) Value(path, name string) (Value, bool, error) {
	parent, err := h.lookup(path)
	if err != nil {
		return Value{}, false, err
	}
	return h.value(parent, name)
}

// SubkeyValues enumerates direct children and reads one named value from each
// without repeatedly resolving the common parent path.
func (h *Hive) SubkeyValues(path, name string) ([]NamedValue, error) {
	parent, err := h.lookup(path)
	if err != nil {
		return nil, err
	}
	children, err := h.readSubkeys(parent)
	if err != nil {
		return nil, err
	}
	result := make([]NamedValue, len(children))
	for index, child := range children {
		value, found, err := h.value(child, name)
		if err != nil {
			return nil, fmt.Errorf("registry hive: read subkey %q value %q: %w", child.name, name, err)
		}
		result[index] = NamedValue{Key: child.name, Value: value, Found: found}
	}
	return result, nil
}

func (h *Hive) value(parent key, name string) (Value, bool, error) {
	if parent.values == 0 || parent.valueList == 0xffffffff {
		return Value{}, false, nil
	}
	list, err := h.readCell(parent.valueList)
	if err != nil {
		return Value{}, false, err
	}
	needed := int64(parent.values) * 4
	if needed > int64(len(list)) {
		return Value{}, false, fmt.Errorf("registry hive: truncated value list for %q", parent.name)
	}
	for offset := int64(0); offset < needed; offset += 4 {
		cell := binary.LittleEndian.Uint32(list[offset : offset+4])
		value, err := h.readValue(cell)
		if err != nil {
			return Value{}, false, err
		}
		if strings.EqualFold(value.Name, name) {
			return value, true, nil
		}
	}
	return Value{}, false, nil
}

func (h *Hive) lookup(path string) (key, error) {
	current, err := h.readKey(h.rootCell)
	if err != nil {
		return key{}, err
	}
	for _, part := range strings.FieldsFunc(strings.Trim(path, `/\`), func(r rune) bool { return r == '/' || r == '\\' }) {
		children, err := h.readSubkeys(current)
		if err != nil {
			return key{}, err
		}
		found := false
		for _, child := range children {
			if strings.EqualFold(child.name, part) {
				current, found = child, true
				break
			}
		}
		if !found {
			return key{}, fmt.Errorf("registry hive: key %q not found", path)
		}
	}
	return current, nil
}

func (h *Hive) readKey(cell uint32) (key, error) {
	data, err := h.readCell(cell)
	if err != nil {
		return key{}, err
	}
	if len(data) < 0x4c || string(data[:2]) != "nk" {
		return key{}, fmt.Errorf("registry hive: cell %#x is not a key", cell)
	}
	nameLength := int(binary.LittleEndian.Uint16(data[0x48:0x4a]))
	if nameLength > len(data)-0x4c {
		return key{}, fmt.Errorf("registry hive: key %#x has truncated name", cell)
	}
	return key{
		name: decodeName(data[0x4c:0x4c+nameLength], binary.LittleEndian.Uint16(data[2:4])&0x20 != 0),
		cell: cell, subkeys: binary.LittleEndian.Uint32(data[0x14:0x18]),
		subkeyList: binary.LittleEndian.Uint32(data[0x1c:0x20]), values: binary.LittleEndian.Uint32(data[0x24:0x28]),
		valueList: binary.LittleEndian.Uint32(data[0x28:0x2c]),
	}, nil
}

func (h *Hive) readSubkeys(parent key) ([]key, error) {
	if parent.subkeys == 0 || parent.subkeyList == 0xffffffff {
		return nil, nil
	}
	cells, err := h.readSubkeyList(parent.subkeyList, 0)
	if err != nil {
		return nil, err
	}
	if len(cells) > maximumSubkeys || uint32(len(cells)) != parent.subkeys {
		return nil, fmt.Errorf("registry hive: key %q subkey count is %d, want %d", parent.name, len(cells), parent.subkeys)
	}
	result := make([]key, len(cells))
	for index, cell := range cells {
		result[index], err = h.readKey(cell)
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}

func (h *Hive) readSubkeyList(cell uint32, depth int) ([]uint32, error) {
	if depth > 32 {
		return nil, fmt.Errorf("registry hive: subkey index nesting exceeds 32")
	}
	data, err := h.readCell(cell)
	if err != nil {
		return nil, err
	}
	if len(data) < 4 {
		return nil, fmt.Errorf("registry hive: truncated subkey index")
	}
	count := int(binary.LittleEndian.Uint16(data[2:4]))
	if count > maximumSubkeys {
		return nil, fmt.Errorf("registry hive: subkey index exceeds %d entries", maximumSubkeys)
	}
	var stride int
	switch string(data[:2]) {
	case "li":
		stride = 4
	case "lf", "lh":
		stride = 8
	case "ri":
		if 4+count*4 > len(data) {
			return nil, fmt.Errorf("registry hive: truncated ri subkey index")
		}
		var result []uint32
		for index := 0; index < count; index++ {
			more, err := h.readSubkeyList(binary.LittleEndian.Uint32(data[4+index*4:]), depth+1)
			if err != nil {
				return nil, err
			}
			if len(result)+len(more) > maximumSubkeys {
				return nil, fmt.Errorf("registry hive: recursive subkey index exceeds %d entries", maximumSubkeys)
			}
			result = append(result, more...)
		}
		return result, nil
	default:
		return nil, fmt.Errorf("registry hive: unsupported subkey index %q", data[:2])
	}
	if 4+count*stride > len(data) {
		return nil, fmt.Errorf("registry hive: truncated %s subkey index", data[:2])
	}
	result := make([]uint32, count)
	for index := range result {
		result[index] = binary.LittleEndian.Uint32(data[4+index*stride:])
	}
	return result, nil
}

func (h *Hive) readValue(cell uint32) (Value, error) {
	data, err := h.readCell(cell)
	if err != nil {
		return Value{}, err
	}
	if len(data) < 0x14 || string(data[:2]) != "vk" {
		return Value{}, fmt.Errorf("registry hive: cell %#x is not a value", cell)
	}
	nameLength := int(binary.LittleEndian.Uint16(data[2:4]))
	if nameLength > len(data)-0x14 {
		return Value{}, fmt.Errorf("registry hive: value %#x has truncated name", cell)
	}
	lengthRaw := binary.LittleEndian.Uint32(data[4:8])
	valueData, err := h.readValueData(lengthRaw, binary.LittleEndian.Uint32(data[8:12]))
	if err != nil {
		return Value{}, err
	}
	return Value{
		Name: decodeName(data[0x14:0x14+nameLength], binary.LittleEndian.Uint16(data[0x10:0x12])&1 != 0),
		Type: binary.LittleEndian.Uint32(data[0x0c:0x10]), Data: valueData,
	}, nil
}

func (h *Hive) readValueData(lengthRaw, cell uint32) ([]byte, error) {
	length := int64(lengthRaw & 0x7fffffff)
	if length == 0 {
		return nil, nil
	}
	if lengthRaw&0x80000000 != 0 {
		if length > 4 {
			return nil, fmt.Errorf("registry hive: inline value is %d bytes", length)
		}
		data := make([]byte, 4)
		binary.LittleEndian.PutUint32(data, cell)
		return data[:length], nil
	}
	data, err := h.readCell(cell)
	if err != nil {
		return nil, err
	}
	if length > int64(len(data)) {
		return nil, fmt.Errorf("registry hive: value data is %d bytes, want %d", len(data), length)
	}
	return append([]byte(nil), data[:length]...), nil
}

func (h *Hive) readCell(cell uint32) ([]byte, error) {
	offset := baseBlockSize + int64(cell)
	if offset < baseBlockSize || offset > h.file.Size()-4 {
		return nil, fmt.Errorf("registry hive: cell %#x exceeds file", cell)
	}
	header := make([]byte, 4)
	if _, err := h.file.ReadAt(header, offset); err != nil {
		return nil, err
	}
	size := int64(int32(binary.LittleEndian.Uint32(header)))
	if size < 0 {
		size = -size
	}
	if size < 4 || size > maximumCellSize || size > h.file.Size()-offset {
		return nil, fmt.Errorf("registry hive: cell %#x has invalid size %d", cell, size)
	}
	data := make([]byte, size-4)
	if _, err := h.file.ReadAt(data, offset+4); err != nil && err != io.EOF {
		return nil, err
	}
	return data, nil
}

func decodeName(data []byte, compressed bool) string {
	if compressed {
		return string(data)
	}
	codepoints := make([]uint16, 0, len(data)/2)
	for offset := 0; offset+1 < len(data); offset += 2 {
		codepoints = append(codepoints, binary.LittleEndian.Uint16(data[offset:offset+2]))
	}
	return string(utf16.Decode(codepoints))
}
