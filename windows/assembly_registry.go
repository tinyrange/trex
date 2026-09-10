package windows

import (
	"encoding/binary"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"io"
	"strconv"
	"strings"

	"go.starlark.net/starlark"
)

// assemblyRegistryDataBuiltin decodes CBS manifest value text into the typed
// values accepted by the native hive writer. Backslashes in quoted multi-
// strings are literal Windows path separators, not string escape characters.
func assemblyRegistryDataBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var kind, value string
	var variables *starlark.Dict
	if err := starlark.UnpackArgs("assembly_registry_data", args, kwargs, "value_type", &kind, "value", &value, "variables?", &variables); err != nil {
		return nil, err
	}
	if variables != nil && strings.Contains(value, "$(") {
		macros := make(map[string]string, variables.Len())
		for _, item := range variables.Items() {
			key, keyOK := starlark.AsString(item[0])
			replacement, valueOK := starlark.AsString(item[1])
			if !keyOK || !valueOK {
				return nil, fmt.Errorf("assembly_registry_data: variables requires string keys and values")
			}
			key = strings.ToLower(key)
			if previous, exists := macros[key]; exists && previous != replacement {
				return nil, fmt.Errorf("assembly_registry_data: conflicting variable %q", key)
			}
			macros[key] = replacement
		}
		var err error
		value, err = expandAssemblyRegistryMacros(value, macros)
		if err != nil {
			return nil, err
		}
	}
	switch strings.ToUpper(kind) {
	case "REG_SZ", "REG_EXPAND_SZ":
		return starlark.String(value), nil
	case "REG_DWORD":
		n, err := strconv.ParseUint(strings.TrimSpace(value), 0, 32)
		if err != nil {
			signed, signedErr := strconv.ParseInt(strings.TrimSpace(value), 0, 32)
			if signedErr != nil {
				return nil, fmt.Errorf("assembly_registry_data: invalid DWORD %q", value)
			}
			n = uint64(uint32(signed))
		}
		return starlark.MakeUint64(n), nil
	case "REG_MULTI_SZ":
		if strings.TrimSpace(value) == "" {
			return starlark.NewList(nil), nil
		}
		reader := csv.NewReader(strings.NewReader(value))
		reader.FieldsPerRecord = -1
		reader.TrimLeadingSpace = true
		fields, err := reader.Read()
		if err != nil {
			return nil, fmt.Errorf("assembly_registry_data: multi-string: %w", err)
		}
		if _, err := reader.Read(); err != io.EOF {
			return nil, fmt.Errorf("assembly_registry_data: multi-string must contain one record")
		}
		values := make([]starlark.Value, len(fields))
		for i, field := range fields {
			if strings.ContainsRune(field, 0) {
				return nil, fmt.Errorf("assembly_registry_data: multi-string contains NUL")
			}
			values[i] = starlark.String(field)
		}
		return starlark.NewList(values), nil
	case "REG_QWORD", "REG_BINARY", "REG_NONE", "REG_RESOURCE_LIST", "REG_RESOURCE_REQUIREMENTS_LIST":
		if strings.EqualFold(kind, "REG_QWORD") && strings.HasPrefix(strings.ToLower(strings.TrimSpace(value)), "0x") {
			n, err := strconv.ParseUint(strings.TrimSpace(value)[2:], 16, 64)
			if err != nil {
				return nil, fmt.Errorf("assembly_registry_data: invalid QWORD %q", value)
			}
			return starlark.MakeUint64(n), nil
		}
		data, err := hex.DecodeString(strings.TrimSpace(value))
		if err != nil {
			return nil, fmt.Errorf("assembly_registry_data: %s: %w", kind, err)
		}
		if strings.EqualFold(kind, "REG_QWORD") {
			if len(data) != 8 {
				return nil, fmt.Errorf("assembly_registry_data: QWORD has %d bytes, want 8", len(data))
			}
			return starlark.MakeUint64(binary.LittleEndian.Uint64(data)), nil
		}
		return starlark.Bytes(data), nil
	default:
		if _, ok := assemblyRegistryNumericType(kind); ok {
			data, err := hex.DecodeString(strings.TrimSpace(value))
			if err != nil {
				return nil, fmt.Errorf("assembly_registry_data: %s: %w", kind, err)
			}
			return starlark.Bytes(data), nil
		}
		return nil, fmt.Errorf("assembly_registry_data: unsupported type %q", kind)
	}
}

// CBS driver manifests spell raw registry types as exactly eight hex digits.
// Preserve all bits: DriverDatabase values include both DEVPROP types such as
// FFFF0012 and installation metadata types such as 00040007. Their data is
// already encoded; treating the low bits as an ordinary REG_* type loses state.
func assemblyRegistryNumericType(kind string) (uint32, bool) {
	if len(kind) != 8 {
		return 0, false
	}
	for _, c := range kind {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return 0, false
		}
	}
	n, err := strconv.ParseUint(kind, 16, 32)
	return uint32(n), err == nil
}

func expandAssemblyRegistryMacros(value string, macros map[string]string) (string, error) {
	var result strings.Builder
	for {
		start := strings.Index(value, "$(")
		if start < 0 {
			result.WriteString(value)
			return result.String(), nil
		}
		result.WriteString(value[:start])
		value = value[start+2:]
		end := strings.IndexByte(value, ')')
		if end < 0 {
			return "", fmt.Errorf("assembly_registry_data: unterminated variable")
		}
		name := value[:end]
		replacement, found := macros[strings.ToLower(name)]
		if !found {
			return "", fmt.Errorf("assembly_registry_data: unknown variable %q", name)
		}
		result.WriteString(replacement)
		value = value[end+1:]
	}
}
