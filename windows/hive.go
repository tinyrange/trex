package windows

import (
	"encoding/binary"
	"fmt"
	"path"
	"strings"
	"unicode/utf16"

	starfile "github.com/tinyrange/trex/storage/star"
	registry "github.com/tinyrange/trex/windows/registry"
	"go.starlark.net/starlark"
)

const hiveBaseBlockSize = 4096

// Hive versions 1.4 and later store values above this threshold in a db
// descriptor. Each segment contributes at most this many bytes, excluding
// the cell's alignment padding.
const hiveBigDataSegmentSize = registry.BigDataSegmentSize

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
	reader   *registry.Hive
	file     starfile.File
	rootCell uint32
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
	reader, err := registry.Open(file)
	if err != nil {
		return nil, err
	}
	return &registryHive{file: file, rootCell: reader.RootCell(), reader: reader}, nil
}

func (h *registryHive) portableReader() (*registry.Hive, error) {
	if h.reader != nil {
		return h.reader, nil
	}
	// A few internal construction tests instantiate registryHive directly.
	// Do not cache here: callers may be inspecting a mutable construction view.
	return registry.Open(h.file)
}

func portableKey(key hiveKey) registry.Key {
	return registry.Key{Name: key.name, Cell: key.cell, Flags: key.flags,
		SecurityCell: key.security, ClassCell: key.classCell, ClassLength: key.classLen,
		SubkeyList: key.subkeyList, SubkeyCount: key.subkeys, ValueList: key.valueList, ValueCount: key.values}
}

func scriptingKey(key registry.Key) hiveKey {
	return hiveKey{name: key.Name, cell: key.Cell, flags: key.Flags,
		security: key.SecurityCell, classCell: key.ClassCell, classLen: key.ClassLength,
		subkeyList: key.SubkeyList, subkeys: key.SubkeyCount, valueList: key.ValueList, values: key.ValueCount}
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
	reader, err := h.portableReader()
	if err != nil {
		return hiveKey{}, err
	}
	key, err := reader.LookupParts(parts)
	return scriptingKey(key), err
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
	reader, err := h.portableReader()
	if err != nil {
		return hiveKey{}, err
	}
	key, err := reader.ReadKey(cell)
	return scriptingKey(key), err
}

func (h *registryHive) readKeySecurity(key hiveKey) ([]byte, error) {
	reader, err := h.portableReader()
	if err != nil {
		return nil, err
	}
	return reader.KeySecurity(portableKey(key))
}

func (h *registryHive) readKeyClass(key hiveKey) ([]byte, error) {
	reader, err := h.portableReader()
	if err != nil {
		return nil, err
	}
	return reader.KeyClass(portableKey(key))
}

func (h *registryHive) readSubkeys(key hiveKey) ([]hiveKey, error) {
	reader, err := h.portableReader()
	if err != nil {
		return nil, err
	}
	keys, err := reader.ReadSubkeys(portableKey(key))
	if err != nil {
		return nil, err
	}
	out := make([]hiveKey, len(keys))
	for i, key := range keys {
		out[i] = scriptingKey(key)
	}
	return out, nil
}

func (h *registryHive) valueCells(key hiveKey) ([]uint32, error) {
	reader, err := h.portableReader()
	if err != nil {
		return nil, err
	}
	return reader.ValueCells(portableKey(key))
}

func (h *registryHive) readValues(key hiveKey) (starlark.IterableMapping, error) {
	cells, err := h.valueCells(key)
	if err != nil {
		return nil, err
	}
	values := starlark.NewDict(len(cells))
	for _, cell := range cells {
		value, err := h.readValue(cell)
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
	reader, err := h.portableReader()
	if err != nil {
		return hiveValue{}, err
	}
	value, err := reader.ReadValue(cell)
	if err != nil {
		return hiveValue{}, err
	}
	name := value.Name
	if name == "" {
		name = "(default)"
	}
	return hiveValue{name: name, typ: value.Type, raw: value.Data, value: hiveValueToStarlark(value.Type, value.Data)}, nil
}

func (h *registryHive) readValueRecords(key hiveKey) (starlark.IterableMapping, error) {
	cells, err := h.valueCells(key)
	if err != nil {
		return nil, err
	}
	values := starlark.NewDict(len(cells))
	for _, cell := range cells {
		value, err := h.readValue(cell)
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
	reader, err := h.portableReader()
	if err != nil {
		return nil, err
	}
	return reader.ReadValueData(lengthRaw, cell)
}

func (h *registryHive) readCell(cell uint32) ([]byte, error) {
	reader, err := h.portableReader()
	if err != nil {
		return nil, err
	}
	return reader.ReadCell(cell)
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

// hiveTraversal bounds whole-tree exports separately from per-key index reads.
// State belongs to one traversal, so repeated API calls remain independent.
type hiveTraversal map[uint32]bool

func (seen hiveTraversal) enter(key hiveKey, depth int) error {
	if depth > 512 {
		return fmt.Errorf("registry hive: key nesting exceeds 512")
	}
	if seen[key.cell] {
		return fmt.Errorf("registry hive: cyclic or repeated key cell %#x", key.cell)
	}
	if len(seen) >= 1<<20 {
		return fmt.Errorf("registry hive: key traversal exceeds entry limit")
	}
	seen[key.cell] = true
	return nil
}
