package windows

import (
	"encoding/binary"
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"path"
	"strings"
	"unicode/utf16"

	"go.starlark.net/starlark"
)

const hiveBaseBlockSize = 4096

func hiveBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("hive", args, kwargs, "file", &value); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("hive: got %s, want file", value.Type())
	}
	return newRegistryHive(file)
}

type registryHive struct {
	file             starfile.File
	rootCell         uint32
	legacyCellPrefix bool
}

type hiveKey struct {
	name       string
	cell       uint32
	flags      uint16
	security   uint32
	classCell  uint32
	classLen   uint16
	subkeyList uint32
	subkeys    uint32
	valueList  uint32
	values     uint32
}

func newRegistryHive(file starfile.File) (*registryHive, error) {
	header := make([]byte, hiveBaseBlockSize)
	if _, err := file.ReadAt(header, 0); err != nil {
		return nil, err
	}
	if string(header[0:4]) != "regf" {
		return nil, fmt.Errorf("hive: invalid regf signature")
	}
	major := binary.LittleEndian.Uint32(header[0x14:0x18])
	minor := binary.LittleEndian.Uint32(header[0x18:0x1c])
	if major != 1 || minor < 1 || minor > 6 {
		return nil, fmt.Errorf("hive: unsupported registry hive format %d.%d", major, minor)
	}
	return &registryHive{
		file:             file,
		rootCell:         binary.LittleEndian.Uint32(header[0x24:0x28]),
		legacyCellPrefix: minor == 1,
	}, nil
}

func (h *registryHive) String() string       { return "<windows.hive>" }
func (h *registryHive) Type() string         { return "hive" }
func (h *registryHive) Freeze()              {}
func (h *registryHive) Truth() starlark.Bool { return starlark.True }
func (h *registryHive) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", h.Type())
}
func (h *registryHive) AttrNames() []string { return []string{"find", "keys", "patches", "root"} }
func (h *registryHive) Attr(name string) (starlark.Value, error) {
	switch name {
	case "find":
		return starlark.NewBuiltin("find", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var value starlark.Value
			if err := starlark.UnpackArgs("find", args, kwargs, "path", &value); err != nil {
				return nil, err
			}
			parts, err := registryPathParts(value)
			if err != nil {
				return nil, fmt.Errorf("find: %w", err)
			}
			record, err := h.lookupParts(parts)
			if err != nil {
				return starlark.None, nil
			}
			return &registryKey{hive: h, key: record, path: registryDisplayPath(parts), parts: parts}, nil
		}), nil
	case "keys":
		return starlark.NewBuiltin("keys", func(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			return hiveKeysBuiltin(thread, builtin, append(starlark.Tuple{h.file}, args...), kwargs)
		}), nil
	case "patches":
		return starlark.NewBuiltin("patches", func(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			return hivePatchesBuiltin(thread, builtin, append(starlark.Tuple{h.file}, args...), kwargs)
		}), nil
	case "root":
		root, err := h.readKey(h.rootCell)
		if err != nil {
			return nil, err
		}
		return &registryKey{hive: h, key: root, path: "/", parts: nil}, nil
	}
	return nil, nil
}
func (h *registryHive) Get(key starlark.Value) (starlark.Value, bool, error) {
	parts, err := registryPathParts(key)
	if err != nil {
		return nil, false, nil
	}
	record, err := h.lookupParts(parts)
	if err != nil {
		return nil, false, err
	}
	return &registryKey{hive: h, key: record, path: registryDisplayPath(parts), parts: parts}, true, nil
}

func (h *registryHive) lookup(name string) (hiveKey, error) {
	parts, err := registryPathParts(starlark.String(name))
	if err != nil {
		return hiveKey{}, err
	}
	return h.lookupParts(parts)
}

func (h *registryHive) lookupParts(parts []string) (hiveKey, error) {
	current, err := h.readKey(h.rootCell)
	if err != nil {
		return hiveKey{}, err
	}
	for _, part := range parts {
		children, err := h.readSubkeys(current)
		if err != nil {
			return hiveKey{}, err
		}
		found := false
		for _, child := range children {
			if strings.EqualFold(child.name, part) {
				current = child
				found = true
				break
			}
		}
		if !found {
			return hiveKey{}, fmt.Errorf("hive: path %q not found", registryDisplayPath(parts))
		}
	}
	return current, nil
}

func registryPathParts(value starlark.Value) ([]string, error) {
	if name, ok := starlark.AsString(value); ok {
		cleaned := path.Clean("/" + strings.TrimPrefix(name, "/"))
		if cleaned == "/" {
			return nil, nil
		}
		return strings.Split(strings.TrimPrefix(cleaned, "/"), "/"), nil
	}
	var values []starlark.Value
	switch value := value.(type) {
	case *starlark.List:
		values = make([]starlark.Value, value.Len())
		for index := range values {
			values[index] = value.Index(index)
		}
	case starlark.Tuple:
		values = []starlark.Value(value)
	default:
		return nil, fmt.Errorf("path is %s, want string, list, or tuple", value.Type())
	}
	parts := make([]string, len(values))
	for index, value := range values {
		part, ok := starlark.AsString(value)
		if !ok {
			return nil, fmt.Errorf("path component %d is %s, want string", index, value.Type())
		}
		if part == "" {
			return nil, fmt.Errorf("path component %d is empty", index)
		}
		parts[index] = part
	}
	return parts, nil
}

func registryDisplayPath(parts []string) string {
	if len(parts) == 0 {
		return "/"
	}
	return "/" + strings.Join(parts, "/")
}

func (h *registryHive) readKey(cell uint32) (hiveKey, error) {
	data, err := h.readCell(cell)
	if err != nil {
		return hiveKey{}, err
	}
	if len(data) < 0x4c || string(data[0:2]) != "nk" {
		return hiveKey{}, fmt.Errorf("hive: cell 0x%x is not a key node", cell)
	}
	flags := binary.LittleEndian.Uint16(data[0x02:0x04])
	nameLength := int(binary.LittleEndian.Uint16(data[0x48:0x4a]))
	nameStart := 0x4c
	nameEnd := nameStart + nameLength
	if nameEnd > len(data) {
		return hiveKey{}, fmt.Errorf("hive: invalid key name length")
	}
	return hiveKey{
		name:       hiveName(data[nameStart:nameEnd], flags),
		cell:       cell,
		flags:      flags,
		security:   binary.LittleEndian.Uint32(data[0x2c:0x30]),
		classCell:  binary.LittleEndian.Uint32(data[0x30:0x34]),
		classLen:   binary.LittleEndian.Uint16(data[0x4a:0x4c]),
		subkeys:    binary.LittleEndian.Uint32(data[0x14:0x18]),
		subkeyList: binary.LittleEndian.Uint32(data[0x1c:0x20]),
		values:     binary.LittleEndian.Uint32(data[0x24:0x28]),
		valueList:  binary.LittleEndian.Uint32(data[0x28:0x2c]),
	}, nil
}

func (h *registryHive) readKeySecurity(key hiveKey) ([]byte, error) {
	if key.security == 0xffffffff {
		return nil, nil
	}
	data, err := h.readCell(key.security)
	if err != nil {
		return nil, err
	}
	if len(data) < 0x14 || string(data[:2]) != "sk" {
		return nil, fmt.Errorf("hive: security cell for key %q is invalid", key.name)
	}
	length := int(binary.LittleEndian.Uint32(data[0x10:0x14]))
	if length > len(data)-0x14 {
		return nil, fmt.Errorf("hive: truncated security descriptor for key %q", key.name)
	}
	return append([]byte(nil), data[0x14:0x14+length]...), nil
}

func (h *registryHive) readKeyClass(key hiveKey) ([]byte, error) {
	if key.classLen == 0 || key.classCell == 0xffffffff {
		return nil, nil
	}
	data, err := h.readCell(key.classCell)
	if err != nil {
		return nil, err
	}
	if int(key.classLen) > len(data) {
		return nil, fmt.Errorf("hive: truncated class data for key %q", key.name)
	}
	return append([]byte(nil), data[:key.classLen]...), nil
}

func (h *registryHive) readSubkeys(key hiveKey) ([]hiveKey, error) {
	if key.subkeys == 0 || key.subkeyList == 0xffffffff {
		return nil, nil
	}
	cells, err := h.readSubkeyList(key.subkeyList)
	if err != nil {
		return nil, err
	}
	keys := make([]hiveKey, 0, len(cells))
	for _, cell := range cells {
		child, err := h.readKey(cell)
		if err != nil {
			return nil, err
		}
		keys = append(keys, child)
	}
	return keys, nil
}

func (h *registryHive) readSubkeyList(cell uint32) ([]uint32, error) {
	data, err := h.readCell(cell)
	if err != nil {
		return nil, err
	}
	if len(data) < 4 {
		return nil, fmt.Errorf("hive: invalid subkey list")
	}
	signature := string(data[0:2])
	count := int(binary.LittleEndian.Uint16(data[2:4]))
	var cells []uint32
	switch signature {
	case "lf", "lh":
		for offset, i := 4, 0; i < count; offset, i = offset+8, i+1 {
			if offset+4 > len(data) {
				return nil, fmt.Errorf("hive: truncated %s subkey list", signature)
			}
			cells = append(cells, binary.LittleEndian.Uint32(data[offset:offset+4]))
		}
	case "li":
		for offset, i := 4, 0; i < count; offset, i = offset+4, i+1 {
			if offset+4 > len(data) {
				return nil, fmt.Errorf("hive: truncated li subkey list")
			}
			cells = append(cells, binary.LittleEndian.Uint32(data[offset:offset+4]))
		}
	case "ri":
		for offset, i := 4, 0; i < count; offset, i = offset+4, i+1 {
			if offset+4 > len(data) {
				return nil, fmt.Errorf("hive: truncated ri subkey list")
			}
			more, err := h.readSubkeyList(binary.LittleEndian.Uint32(data[offset : offset+4]))
			if err != nil {
				return nil, err
			}
			cells = append(cells, more...)
		}
	default:
		return nil, fmt.Errorf("hive: unsupported subkey list %q", signature)
	}
	return cells, nil
}

func (h *registryHive) readValues(key hiveKey) (starlark.IterableMapping, error) {
	values := starlark.NewDict(int(key.values))
	if key.values == 0 || key.valueList == 0xffffffff {
		return values, nil
	}
	list, err := h.readCell(key.valueList)
	if err != nil {
		return nil, err
	}
	needed := int(key.values) * 4
	if needed > len(list) {
		return nil, fmt.Errorf("hive: truncated value list")
	}
	for offset := 0; offset < needed; offset += 4 {
		value, err := h.readValue(binary.LittleEndian.Uint32(list[offset : offset+4]))
		if err != nil {
			return nil, err
		}
		if err := values.SetKey(starlark.String(value.name), value.value); err != nil {
			return nil, err
		}
	}
	return values, nil
}

type hiveValue struct {
	name  string
	typ   uint32
	raw   []byte
	value starlark.Value
}

func (h *registryHive) readValue(cell uint32) (hiveValue, error) {
	data, err := h.readCell(cell)
	if err != nil {
		return hiveValue{}, err
	}
	if len(data) < 0x14 || string(data[0:2]) != "vk" {
		return hiveValue{}, fmt.Errorf("hive: cell 0x%x is not a value node", cell)
	}
	nameLength := int(binary.LittleEndian.Uint16(data[0x02:0x04]))
	dataLengthRaw := binary.LittleEndian.Uint32(data[0x04:0x08])
	dataCell := binary.LittleEndian.Uint32(data[0x08:0x0c])
	valueType := binary.LittleEndian.Uint32(data[0x0c:0x10])
	flags := binary.LittleEndian.Uint16(data[0x10:0x12])
	nameStart := 0x14
	nameEnd := nameStart + nameLength
	if nameEnd > len(data) {
		return hiveValue{}, fmt.Errorf("hive: invalid value name length")
	}
	valueData, err := h.readValueData(dataLengthRaw, dataCell)
	if err != nil {
		return hiveValue{}, err
	}
	return hiveValue{
		name:  hiveValueName(data[nameStart:nameEnd], flags),
		typ:   valueType,
		raw:   valueData,
		value: hiveValueToStarlark(valueType, valueData),
	}, nil
}

func (h *registryHive) readValueRecords(key hiveKey) (starlark.IterableMapping, error) {
	values := starlark.NewDict(int(key.values))
	if key.values == 0 || key.valueList == 0xffffffff {
		return values, nil
	}
	list, err := h.readCell(key.valueList)
	if err != nil {
		return nil, err
	}
	needed := int(key.values) * 4
	if needed > len(list) {
		return nil, fmt.Errorf("hive: truncated value list")
	}
	for offset := 0; offset < needed; offset += 4 {
		value, err := h.readValue(binary.LittleEndian.Uint32(list[offset : offset+4]))
		if err != nil {
			return nil, err
		}
		record := starfile.NewRecord(map[string]starlark.Value{
			"raw":   starlark.Bytes(value.raw),
			"type":  starlark.MakeUint64(uint64(value.typ)),
			"value": value.value,
		})
		if err := values.SetKey(starlark.String(value.name), record); err != nil {
			return nil, err
		}
	}
	return values, nil
}

func (h *registryHive) readValueData(lengthRaw uint32, cell uint32) ([]byte, error) {
	inline := lengthRaw&0x80000000 != 0
	length := int(lengthRaw & 0x7fffffff)
	if length == 0 {
		return nil, nil
	}
	if inline {
		if length > 4 {
			return nil, fmt.Errorf("hive: invalid inline value length")
		}
		data := make([]byte, 4)
		binary.LittleEndian.PutUint32(data, cell)
		return data[:length], nil
	}
	data, err := h.readCell(cell)
	if err != nil {
		return nil, err
	}
	if length > len(data) {
		if len(data) < 8 || string(data[:2]) != "db" {
			return nil, fmt.Errorf("hive: truncated value data")
		}
		count := int(binary.LittleEndian.Uint16(data[2:4]))
		listCell := binary.LittleEndian.Uint32(data[4:8])
		list, err := h.readCell(listCell)
		if err != nil {
			return nil, fmt.Errorf("hive: read large-value segment list: %w", err)
		}
		if count < 1 || count > len(list)/4 {
			return nil, fmt.Errorf("hive: truncated large-value segment list")
		}
		value := make([]byte, 0, length)
		for index := 0; index < count && len(value) < length; index++ {
			segmentCell := binary.LittleEndian.Uint32(list[index*4 : index*4+4])
			segment, err := h.readCell(segmentCell)
			if err != nil {
				return nil, fmt.Errorf("hive: read large-value segment %d: %w", index, err)
			}
			remaining := length - len(value)
			if len(segment) > remaining {
				segment = segment[:remaining]
			}
			value = append(value, segment...)
		}
		if len(value) != length {
			return nil, fmt.Errorf("hive: large value has %d bytes, want %d", len(value), length)
		}
		return value, nil
	}
	return data[:length], nil
}

func (h *registryHive) readCell(cell uint32) ([]byte, error) {
	offset := int64(hiveBaseBlockSize + cell)
	header := make([]byte, 4)
	if _, err := h.file.ReadAt(header, offset); err != nil {
		return nil, err
	}
	size := int32(binary.LittleEndian.Uint32(header))
	if size == 0 {
		return nil, fmt.Errorf("hive: empty cell 0x%x", cell)
	}
	if size < 0 {
		size = -size
	}
	prefix := int32(0)
	if h.legacyCellPrefix {
		prefix = 4
	}
	if size < 4+prefix {
		return nil, fmt.Errorf("hive: invalid cell 0x%x size %d", cell, size)
	}
	data := make([]byte, int(size)-4-int(prefix))
	if _, err := h.file.ReadAt(data, offset+4+int64(prefix)); err != nil {
		return nil, err
	}
	return data, nil
}

func hiveName(raw []byte, flags uint16) string {
	if flags&0x20 != 0 {
		return string(raw)
	}
	codepoints := make([]uint16, 0, len(raw)/2)
	for offset := 0; offset+1 < len(raw); offset += 2 {
		codepoints = append(codepoints, binary.LittleEndian.Uint16(raw[offset:offset+2]))
	}
	return string(utf16.Decode(codepoints))
}

func hiveValueName(raw []byte, flags uint16) string {
	name := string(raw)
	if flags&0x01 == 0 {
		name = decodeUTF16LE(raw)
	}
	if name == "" {
		return "(default)"
	}
	return name
}

func hiveValueToStarlark(valueType uint32, data []byte) starlark.Value {
	switch valueType {
	case 1, 2:
		return starlark.String(strings.TrimRight(decodeUTF16LE(data), "\x00"))
	case 4:
		if len(data) < 4 {
			return starlark.None
		}
		return starlark.MakeUint64(uint64(binary.LittleEndian.Uint32(data)))
	case 11:
		if len(data) < 8 {
			return starlark.None
		}
		return starlark.MakeUint64(binary.LittleEndian.Uint64(data))
	case 7:
		parts := strings.Split(strings.TrimRight(decodeUTF16LE(data), "\x00"), "\x00")
		values := make([]starlark.Value, 0, len(parts))
		for _, part := range parts {
			if part != "" {
				values = append(values, starlark.String(part))
			}
		}
		return starlark.NewList(values)
	}
	return starlark.Bytes(data)
}

func decodeUTF16LE(data []byte) string {
	codepoints := make([]uint16, 0, len(data)/2)
	for offset := 0; offset+1 < len(data); offset += 2 {
		codepoints = append(codepoints, binary.LittleEndian.Uint16(data[offset:offset+2]))
	}
	return string(utf16.Decode(codepoints))
}

func registryDataString(value registryData) string {
	if value.typ != regSZ && value.typ != regExpandSZ {
		return ""
	}
	return strings.TrimRight(decodeUTF16LE(value.data), "\x00")
}

type registryKey struct {
	hive  *registryHive
	key   hiveKey
	path  string
	parts []string
}

func (k *registryKey) String() string {
	files, err := k.files()
	if err != nil {
		return fmt.Sprintf("<windows.hive.key %q read error: %v>", k.path, err)
	}
	return files.String()
}
func (k *registryKey) Type() string         { return "hive.key" }
func (k *registryKey) Freeze()              {}
func (k *registryKey) Truth() starlark.Bool { return starlark.True }
func (k *registryKey) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", k.Type())
}
func (k *registryKey) Get(key starlark.Value) (starlark.Value, bool, error) {
	name, isString := starlark.AsString(key)
	parts, err := registryPathParts(key)
	if err != nil {
		return nil, false, nil
	}
	if !isString || !strings.HasPrefix(name, "/") {
		parts = append(append([]string(nil), k.parts...), parts...)
	}
	record, err := k.hive.lookupParts(parts)
	if err != nil {
		return nil, false, err
	}
	return &registryKey{hive: k.hive, key: record, path: registryDisplayPath(parts), parts: parts}, true, nil
}
func (k *registryKey) Attr(name string) (starlark.Value, error) {
	switch name {
	case "children":
		children, err := k.hive.readSubkeys(k.key)
		if err != nil {
			return nil, err
		}
		values := make([]starlark.Value, len(children))
		for index, child := range children {
			parts := append(append([]string(nil), k.parts...), child.name)
			values[index] = &registryKey{hive: k.hive, key: child, path: registryDisplayPath(parts), parts: parts}
		}
		return starlark.NewList(values), nil
	case "files":
		return k.files()
	case "name":
		return starlark.String(k.key.name), nil
	case "path_parts":
		values := make([]starlark.Value, len(k.parts))
		for index, part := range k.parts {
			values[index] = starlark.String(part)
		}
		return starlark.NewList(values), nil
	case "values":
		return k.hive.readValues(k.key)
	case "value_records":
		return k.hive.readValueRecords(k.key)
	}
	return nil, nil
}
func (k *registryKey) AttrNames() []string {
	return []string{"children", "files", "name", "path_parts", "value_records", "values"}
}
func (k *registryKey) files() (*starlark.List, error) {
	children, err := k.hive.readSubkeys(k.key)
	if err != nil {
		return nil, err
	}
	values := make([]starlark.Value, len(children))
	for idx, child := range children {
		values[idx] = starlark.String(path.Join(k.path, child.name))
	}
	return starlark.NewList(values), nil
}
