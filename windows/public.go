package windows

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"sort"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func DecodeUTF16LE(data []byte) string                   { return decodeUTF16LE(data) }
func ScanUTF16Strings(data []byte, minimum int) []string { return scanUTF16Strings(data, minimum) }

func INFJSON(file starfile.File) (string, error) {
	data, err := starfile.ReadAll(file)
	if err != nil {
		return "", err
	}
	parsed, err := parseINF(decodeINFText(data))
	if err != nil {
		return "", err
	}
	native, err := starlarkNative(parsed)
	if err != nil {
		return "", err
	}
	encoded, err := json.MarshalIndent(native, "", "  ")
	return string(encoded), err
}

type PEImport struct {
	DLL, Name     string
	Ordinal, Hint uint16
	IATRVA        uint32
}
type PEExport struct {
	Name         string
	Ordinal, RVA uint32
	Forwarder    string
}

func PEImports(data []byte) ([]PEImport, error) {
	imports, err := peImports(data)
	if err != nil {
		return nil, err
	}
	result := make([]PEImport, len(imports))
	for i, item := range imports {
		result[i] = PEImport{DLL: item.dll, Name: item.name, Ordinal: item.ordinal, Hint: item.hint, IATRVA: item.iatRVA}
	}
	return result, nil
}
func PEExports(data []byte) ([]PEExport, error) {
	exports, err := peExports(data)
	if err != nil {
		return nil, err
	}
	result := make([]PEExport, len(exports))
	for i, item := range exports {
		result[i] = PEExport{Name: item.name, Ordinal: item.ordinal, RVA: item.rva, Forwarder: item.forwarder}
	}
	return result, nil
}

type HiveEntry struct {
	Name      string
	Directory bool
	File      starfile.File
}

// Hive exposes path-based registry inspection without leaking the parser's
// on-disk cell representation.
type Hive struct {
	parsed *registryHive
}

type RegistryValue struct {
	Name string
	Type uint32
	Data []byte
}

const RegistryTypeNone = regNone

func OpenHive(file starfile.File) (*Hive, error) {
	parsed, err := newRegistryHive(file)
	if err != nil {
		return nil, err
	}
	return &Hive{parsed: parsed}, nil
}

func (h *Hive) HasKey(name string) bool {
	_, err := h.parsed.lookup(name)
	return err == nil
}

func (h *Hive) Lookup(name string) error {
	_, err := h.parsed.lookup(name)
	return err
}

func (h *Hive) RawValues(name string) ([]RegistryValue, error) {
	key, err := h.parsed.lookup(name)
	if err != nil {
		return nil, err
	}
	values, err := h.parsed.readRawValues(key)
	if err != nil {
		return nil, err
	}
	result := make([]RegistryValue, len(values))
	for index, value := range values {
		result[index] = RegistryValue{
			Name: value.name,
			Type: value.value.typ,
			Data: append([]byte(nil), value.value.data...),
		}
	}
	return result, nil
}

func RegistrySID(authority byte, subauthorities ...uint32) []byte {
	return registrySID(authority, subauthorities...)
}

func HiveEntries(file starfile.File) ([]HiveEntry, error) {
	hive, err := newRegistryHive(file)
	if err != nil {
		return nil, err
	}
	root, err := hive.lookup("/")
	if err != nil {
		return nil, err
	}
	var result []HiveEntry
	var walk func(hiveKey, string) error
	walk = func(key hiveKey, name string) error {
		result = append(result, HiveEntry{Name: name, Directory: true})
		values, err := hive.readValues(key)
		if err != nil {
			return err
		}
		native, err := starlarkNative(values)
		if err != nil {
			return err
		}
		if object, ok := native.(map[string]any); ok && len(object) != 0 {
			data, err := json.MarshalIndent(native, "", "  ")
			if err != nil {
				return err
			}
			data = append(data, '\n')
			valueName := path.Join(name, "_values.json")
			result = append(result, HiveEntry{Name: valueName, File: &starfile.Bytes{Name: valueName, Data: data}})
		}
		children, err := hive.readSubkeys(key)
		if err != nil {
			return err
		}
		sort.Slice(children, func(i, j int) bool { return children[i].name < children[j].name })
		for _, child := range children {
			if err := walk(child, path.Join(name, child.name)); err != nil {
				return err
			}
		}
		return nil
	}
	return result, walk(root, "/")
}

func HiveJSON(file starfile.File, maximumDepth int) (string, error) {
	hive, err := newRegistryHive(file)
	if err != nil {
		return "", err
	}
	root, err := hive.lookup("/")
	if err != nil {
		return "", err
	}
	var build func(hiveKey, string, int) (map[string]any, error)
	build = func(key hiveKey, name string, depth int) (map[string]any, error) {
		values, err := hive.readValues(key)
		if err != nil {
			return nil, err
		}
		native, err := starlarkNative(values)
		if err != nil {
			return nil, err
		}
		result := map[string]any{"path": name, "values": native}
		if depth >= maximumDepth {
			result["truncated"] = true
			return result, nil
		}
		children, err := hive.readSubkeys(key)
		if err != nil {
			return nil, err
		}
		items := make([]map[string]any, 0, len(children))
		for _, child := range children {
			item, err := build(child, path.Join(name, child.name), depth+1)
			if err != nil {
				return nil, err
			}
			items = append(items, item)
		}
		result["keys"] = items
		return result, nil
	}
	value, err := build(root, "/", 0)
	if err != nil {
		return "", err
	}
	data, err := json.MarshalIndent(value, "", "  ")
	return string(data), err
}

func starlarkNative(value starlark.Value) (any, error) {
	switch value := value.(type) {
	case starlark.NoneType:
		return nil, nil
	case starlark.Bool:
		return bool(value), nil
	case starlark.String:
		return string(value), nil
	case starlark.Bytes:
		return hex.EncodeToString([]byte(value)), nil
	case starlark.Int:
		if number, ok := value.Int64(); ok {
			return number, nil
		}
		return value.String(), nil
	case *starlark.List:
		result := make([]any, value.Len())
		for i := range result {
			item, err := starlarkNative(value.Index(i))
			if err != nil {
				return nil, err
			}
			result[i] = item
		}
		return result, nil
	case *starlark.Dict:
		result := make(map[string]any, value.Len())
		for _, item := range value.Items() {
			key, ok := starlark.AsString(item[0])
			if !ok {
				return nil, fmt.Errorf("registry value key is %s", item[0].Type())
			}
			decoded, err := starlarkNative(item[1])
			if err != nil {
				return nil, err
			}
			result[key] = decoded
		}
		return result, nil
	default:
		return value.String(), nil
	}
}
