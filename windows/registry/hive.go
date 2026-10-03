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
	// BigDataSegmentSize is the payload capacity of a REGF 1.4+ db segment.
	BigDataSegmentSize = 0x3fd8
)

type Hive struct {
	file     storage.Reader
	rootCell uint32
	minor    uint32
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

// Key describes an nk cell. Cell references are relative to the hive bins,
// never host offsets or paths. Use the Hive methods to decode their contents.
type Key struct {
	Name         string
	Cell         uint32
	Flags        uint16
	SecurityCell uint32
	ClassCell    uint32
	ClassLength  uint16
	SubkeyList   uint32
	SubkeyCount  uint32
	ValueList    uint32
	ValueCount   uint32
}

// RootCell returns the cell reference recorded by the base block.
func (h *Hive) RootCell() uint32 { return h.rootCell }

// MinorVersion returns the validated REGF 1.x generation.
func (h *Hive) MinorVersion() uint32 { return h.minor }

func Open(file storage.Reader) (*Hive, error) {
	if file == nil || file.Size() < baseBlockSize {
		return nil, fmt.Errorf("registry hive: file is smaller than one base block")
	}
	header := make([]byte, baseBlockSize)
	if err := readFullAt(file, header, 0); err != nil {
		return nil, fmt.Errorf("registry hive: read base block: %w", err)
	}
	if string(header[:4]) != "regf" {
		return nil, fmt.Errorf("registry hive: invalid regf signature")
	}
	major, minor := binary.LittleEndian.Uint32(header[0x14:]), binary.LittleEndian.Uint32(header[0x18:])
	if major != 1 || minor < 1 || minor > 6 {
		return nil, fmt.Errorf("registry hive: unsupported registry hive format %d.%d", major, minor)
	}
	return &Hive{file: file, rootCell: binary.LittleEndian.Uint32(header[0x24:0x28]), minor: minor}, nil
}

func (h *Hive) Subkeys(path string) ([]string, error) {
	parent, err := h.lookup(path)
	if err != nil {
		return nil, err
	}
	children, err := h.ReadSubkeys(parent)
	if err != nil {
		return nil, err
	}
	result := make([]string, len(children))
	for index, child := range children {
		result[index] = child.Name
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
	children, err := h.ReadSubkeys(parent)
	if err != nil {
		return nil, err
	}
	result := make([]NamedValue, len(children))
	for index, child := range children {
		value, found, err := h.value(child, name)
		if err != nil {
			return nil, fmt.Errorf("registry hive: read subkey %q value %q: %w", child.Name, name, err)
		}
		result[index] = NamedValue{Key: child.Name, Value: value, Found: found}
	}
	return result, nil
}

func (h *Hive) value(parent Key, name string) (Value, bool, error) {
	if parent.ValueCount == 0 || parent.ValueList == 0xffffffff {
		return Value{}, false, nil
	}
	list, err := h.ReadCell(parent.ValueList)
	if err != nil {
		return Value{}, false, err
	}
	needed := int64(parent.ValueCount) * 4
	if needed > int64(len(list)) {
		return Value{}, false, fmt.Errorf("registry hive: truncated value list for %q", parent.Name)
	}
	for offset := int64(0); offset < needed; offset += 4 {
		cell := binary.LittleEndian.Uint32(list[offset : offset+4])
		value, err := h.ReadValue(cell)
		if err != nil {
			return Value{}, false, err
		}
		if strings.EqualFold(value.Name, name) {
			return value, true, nil
		}
	}
	return Value{}, false, nil
}

func (h *Hive) lookup(path string) (Key, error) {
	return h.LookupParts(strings.FieldsFunc(strings.Trim(path, `/\`), func(r rune) bool { return r == '/' || r == '\\' }))
}

// LookupParts resolves literal key names, preserving slash characters within a
// component. Textual path splitting remains the responsibility of each adapter.
func (h *Hive) LookupParts(parts []string) (Key, error) {
	current, err := h.ReadKey(h.rootCell)
	if err != nil {
		return Key{}, err
	}
	for _, part := range parts {
		children, err := h.ReadSubkeys(current)
		if err != nil {
			return Key{}, err
		}
		found := false
		for _, child := range children {
			if strings.EqualFold(child.Name, part) {
				current, found = child, true
				break
			}
		}
		if !found {
			return Key{}, fmt.Errorf("registry hive: key component %q not found", part)
		}
	}
	return current, nil
}

// ReadKey decodes an nk cell, including its class and security references.
func (h *Hive) ReadKey(cell uint32) (Key, error) {
	data, err := h.ReadCell(cell)
	if err != nil {
		return Key{}, err
	}
	if len(data) < 0x4c || string(data[:2]) != "nk" {
		return Key{}, fmt.Errorf("registry hive: cell %#x is not a key", cell)
	}
	nameLength := int(binary.LittleEndian.Uint16(data[0x48:]))
	if nameLength > len(data)-0x4c {
		return Key{}, fmt.Errorf("registry hive: key %#x has truncated name", cell)
	}
	return Key{
		Name: decodeName(data[0x4c:0x4c+nameLength], binary.LittleEndian.Uint16(data[2:4])&0x20 != 0),
		Cell: cell, Flags: binary.LittleEndian.Uint16(data[2:4]),
		SecurityCell: binary.LittleEndian.Uint32(data[0x2c:]),
		ClassCell:    binary.LittleEndian.Uint32(data[0x30:]), ClassLength: binary.LittleEndian.Uint16(data[0x4a:]),
		SubkeyCount: binary.LittleEndian.Uint32(data[0x14:]), SubkeyList: binary.LittleEndian.Uint32(data[0x1c:]),
		ValueCount: binary.LittleEndian.Uint32(data[0x24:]), ValueList: binary.LittleEndian.Uint32(data[0x28:]),
	}, nil
}

// ReadSubkeys returns the direct child keys after validating the declared count.
func (h *Hive) ReadSubkeys(parent Key) ([]Key, error) {
	if parent.SubkeyCount == 0 || parent.SubkeyList == 0xffffffff {
		return nil, nil
	}
	cells, err := h.SubkeyCells(parent.SubkeyList)
	if err != nil {
		return nil, err
	}
	if len(cells) > maximumSubkeys || uint32(len(cells)) != parent.SubkeyCount {
		return nil, fmt.Errorf("registry hive: key %q subkey count is %d, want %d", parent.Name, len(cells), parent.SubkeyCount)
	}
	result := make([]Key, len(cells))
	for index, cell := range cells {
		result[index], err = h.ReadKey(cell)
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}

// SubkeyCells expands bounded li/lf/lh/ri indexes and rejects repeated cells.
func (h *Hive) SubkeyCells(cell uint32) ([]uint32, error) {
	seen := make(map[uint32]bool)
	var result []uint32
	var walk func(uint32, int) error
	walk = func(cell uint32, depth int) error {
		if depth > 32 {
			return fmt.Errorf("registry hive: subkey index nesting exceeds 32")
		}
		if seen[cell] {
			return fmt.Errorf("registry hive: cyclic or repeated subkey index %#x", cell)
		}
		if len(seen) >= maximumSubkeys {
			return fmt.Errorf("registry hive: subkey index exceeds cell limit")
		}
		seen[cell] = true
		data, err := h.ReadCell(cell)
		if err != nil {
			return err
		}
		if len(data) < 4 {
			return fmt.Errorf("registry hive: truncated subkey index")
		}
		count := int(binary.LittleEndian.Uint16(data[2:]))
		stride := 4
		signature := string(data[:2])
		switch signature {
		case "li", "ri":
		case "lf", "lh":
			stride = 8
		default:
			return fmt.Errorf("registry hive: unsupported subkey index %q", signature)
		}
		if count > (len(data)-4)/stride {
			return fmt.Errorf("registry hive: truncated %s subkey index", signature)
		}
		if signature != "ri" && count > maximumSubkeys-len(result) {
			return fmt.Errorf("registry hive: subkey index exceeds entry limit")
		}
		for index := 0; index < count; index++ {
			child := binary.LittleEndian.Uint32(data[4+index*stride:])
			if signature == "ri" {
				if err := walk(child, depth+1); err != nil {
					return err
				}
			} else {
				result = append(result, child)
			}
		}
		return nil
	}
	if err := walk(cell, 0); err != nil {
		return nil, err
	}
	return result, nil
}

// ValueCells validates the value list before its callers allocate result maps.
func (h *Hive) ValueCells(key Key) ([]uint32, error) {
	if key.ValueCount == 0 || key.ValueList == 0xffffffff {
		return nil, nil
	}
	data, err := h.ReadCell(key.ValueList)
	if err != nil {
		return nil, err
	}
	if uint64(key.ValueCount) > uint64(len(data)/4) {
		return nil, fmt.Errorf("registry hive: truncated value list for %q", key.Name)
	}
	cells := make([]uint32, key.ValueCount)
	for i := range cells {
		cells[i] = binary.LittleEndian.Uint32(data[i*4:])
	}
	return cells, nil
}

// KeySecurity reads a key's raw self-relative security descriptor.
func (h *Hive) KeySecurity(key Key) ([]byte, error) {
	if key.SecurityCell == 0xffffffff {
		return nil, nil
	}
	data, err := h.ReadCell(key.SecurityCell)
	if err != nil {
		return nil, err
	}
	if len(data) < 0x14 || string(data[:2]) != "sk" {
		return nil, fmt.Errorf("registry hive: invalid security cell for %q", key.Name)
	}
	length := uint64(binary.LittleEndian.Uint32(data[0x10:]))
	if length > uint64(len(data)-0x14) {
		return nil, fmt.Errorf("registry hive: truncated security descriptor for %q", key.Name)
	}
	return data[0x14 : 0x14+length], nil
}

// KeyClass reads the uninterpreted key class bytes.
func (h *Hive) KeyClass(key Key) ([]byte, error) {
	if key.ClassLength == 0 || key.ClassCell == 0xffffffff {
		return nil, nil
	}
	data, err := h.ReadCell(key.ClassCell)
	if err != nil {
		return nil, err
	}
	if int(key.ClassLength) > len(data) {
		return nil, fmt.Errorf("registry hive: truncated class data for %q", key.Name)
	}
	return data[:key.ClassLength], nil
}

func (h *Hive) ReadValue(cell uint32) (Value, error) {
	data, err := h.ReadCell(cell)
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
	valueData, err := h.ReadValueData(lengthRaw, binary.LittleEndian.Uint32(data[8:12]))
	if err != nil {
		return Value{}, err
	}
	return Value{
		Name: decodeName(data[0x14:0x14+nameLength], binary.LittleEndian.Uint16(data[0x10:0x12])&1 != 0),
		Type: binary.LittleEndian.Uint32(data[0x0c:0x10]), Data: valueData,
	}, nil
}

// ReadValueData decodes inline, direct and REGF 1.4+ segmented value data.
func (h *Hive) ReadValueData(lengthRaw, cell uint32) ([]byte, error) {
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
	if length > maximumCellSize || length > h.file.Size() {
		return nil, fmt.Errorf("registry hive: value size %d exceeds bounds", length)
	}
	data, err := h.ReadCell(cell)
	if err != nil {
		return nil, err
	}
	segmented := length > BigDataSegmentSize && h.minor >= 4
	if !segmented && length <= int64(len(data)) {
		return data[:length], nil
	}
	if len(data) < 8 || string(data[:2]) != "db" {
		return nil, fmt.Errorf("registry hive: truncated value data")
	}
	count := int(binary.LittleEndian.Uint16(data[2:]))
	if int64(count) != (length+BigDataSegmentSize-1)/BigDataSegmentSize {
		return nil, fmt.Errorf("registry hive: invalid large-value segment count %d", count)
	}
	list, err := h.ReadCell(binary.LittleEndian.Uint32(data[4:]))
	if err != nil {
		return nil, err
	}
	if count < 1 || count > len(list)/4 {
		return nil, fmt.Errorf("registry hive: truncated large-value segment list")
	}
	value := make([]byte, 0, length)
	for index := 0; index < count; index++ {
		segment, err := h.ReadCell(binary.LittleEndian.Uint32(list[index*4:]))
		if err != nil {
			return nil, fmt.Errorf("registry hive: large-value segment %d: %w", index, err)
		}
		if len(segment) < BigDataSegmentSize {
			return nil, fmt.Errorf("registry hive: truncated large-value segment %d", index)
		}
		needed := min(length-int64(len(value)), BigDataSegmentSize)
		value = append(value, segment[:needed]...)
	}
	return value, nil
}

// ReadCell returns the allocated bytes of one cell, excluding the NT 3.1 link
// prefix and size word. Returned bytes are independent of the source.
func (h *Hive) ReadCell(cell uint32) ([]byte, error) {
	offset := baseBlockSize + int64(cell)
	if offset > h.file.Size()-4 {
		return nil, fmt.Errorf("registry hive: cell %#x exceeds file", cell)
	}
	var header [4]byte
	if err := readFullAt(h.file, header[:], offset); err != nil {
		return nil, err
	}
	size := int64(int32(binary.LittleEndian.Uint32(header[:])))
	if size < 0 {
		size = -size
	}
	prefix := int64(0)
	if h.minor == 1 {
		prefix = 4
	}
	if size < 4+prefix || size > maximumCellSize || size > h.file.Size()-offset {
		return nil, fmt.Errorf("registry hive: cell %#x has invalid size %d", cell, size)
	}
	data := make([]byte, size-4-prefix)
	if err := readFullAt(h.file, data, offset+4+prefix); err != nil {
		return nil, err
	}
	return data, nil
}

func readFullAt(file storage.Reader, data []byte, offset int64) error {
	n, err := file.ReadAt(data, offset)
	if n == len(data) {
		return nil
	}
	if err == nil || err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return err
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
