package json

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"sort"
	"strconv"
	"strings"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

const defaultJSONDecodeLimit = 64 << 20

func Builtins() starlark.StringDict {
	return starlark.StringDict{
		"encode": starlark.NewBuiltin("encode", jsonEncodeBuiltin),
		"decode": starlark.NewBuiltin("decode", jsonDecodeBuiltin),
	}
}

func jsonDecodeBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	maximum := defaultJSONDecodeLimit
	if err := starlark.UnpackArgs("decode", args, kwargs, "value", &value, "maximum?", &maximum); err != nil {
		return nil, err
	}
	if maximum < 0 {
		return nil, fmt.Errorf("json.decode: maximum must be non-negative")
	}
	data, err := starfile.BytesForValue(value, int64(maximum))
	if err != nil {
		return nil, fmt.Errorf("json.decode: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var decoded any
	if err := decoder.Decode(&decoded); err != nil {
		return nil, fmt.Errorf("json.decode: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("json.decode: multiple JSON values")
		}
		return nil, fmt.Errorf("json.decode: trailing data: %w", err)
	}
	return jsonToStarlark(decoded)
}

func jsonToStarlark(value any) (starlark.Value, error) {
	switch value := value.(type) {
	case nil:
		return starlark.None, nil
	case bool:
		return starlark.Bool(value), nil
	case string:
		return starlark.String(value), nil
	case json.Number:
		text := value.String()
		if !strings.ContainsAny(text, ".eE") {
			integer, ok := new(big.Int).SetString(text, 10)
			if !ok {
				return nil, fmt.Errorf("json.decode: invalid number %q", text)
			}
			return starlark.MakeBigInt(integer), nil
		}
		floating, err := strconv.ParseFloat(text, 64)
		if err != nil {
			return nil, fmt.Errorf("json.decode: invalid number %q", text)
		}
		return starlark.Float(floating), nil
	case []any:
		items := make([]starlark.Value, len(value))
		for index, item := range value {
			converted, err := jsonToStarlark(item)
			if err != nil {
				return nil, err
			}
			items[index] = converted
		}
		return starlark.NewList(items), nil
	case map[string]any:
		keys := make([]string, 0, len(value))
		for key := range value {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		result := starlark.NewDict(len(keys))
		for _, key := range keys {
			converted, err := jsonToStarlark(value[key])
			if err != nil {
				return nil, err
			}
			if err := result.SetKey(starlark.String(key), converted); err != nil {
				return nil, err
			}
		}
		return result, nil
	default:
		return nil, fmt.Errorf("json.decode: unsupported decoded value %T", value)
	}
}

func jsonEncodeBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	indentValue := starlark.Value(starlark.None)
	if err := starlark.UnpackArgs("encode", args, kwargs, "value", &value, "indent?", &indentValue); err != nil {
		return nil, err
	}
	indent, err := jsonIndent(indentValue)
	if err != nil {
		return nil, err
	}
	native, err := starlarkToJSON(value)
	if err != nil {
		return nil, err
	}
	var data []byte
	if indent == "" {
		data, err = json.Marshal(native)
	} else {
		data, err = json.MarshalIndent(native, "", indent)
	}
	if err != nil {
		return nil, err
	}
	return starlark.String(string(data)), nil
}

func jsonIndent(value starlark.Value) (string, error) {
	switch value := value.(type) {
	case starlark.NoneType:
		return "", nil
	case starlark.String:
		return string(value), nil
	case starlark.Int:
		width, ok := value.Int64()
		if !ok || width < 0 {
			return "", fmt.Errorf("json.encode: indent must be a non-negative integer")
		}
		return strings.Repeat(" ", int(width)), nil
	default:
		return "", fmt.Errorf("json.encode: got %s for indent, want int or string", value.Type())
	}
}

func starlarkToJSON(value starlark.Value) (any, error) {
	switch value := value.(type) {
	case starlark.NoneType:
		return nil, nil
	case starlark.Bool:
		return bool(value), nil
	case starlark.Int:
		if i, ok := value.Int64(); ok {
			return i, nil
		}
		return value.String(), nil
	case starlark.Float:
		return float64(value), nil
	case starlark.String:
		return string(value), nil
	case starlark.Bytes:
		return []byte(value), nil
	case *starlark.List:
		values := make([]any, 0, value.Len())
		iter := value.Iterate()
		defer iter.Done()
		var item starlark.Value
		for iter.Next(&item) {
			converted, err := starlarkToJSON(item)
			if err != nil {
				return nil, err
			}
			values = append(values, converted)
		}
		return values, nil
	case starlark.Tuple:
		values := make([]any, 0, value.Len())
		for _, item := range value {
			converted, err := starlarkToJSON(item)
			if err != nil {
				return nil, err
			}
			values = append(values, converted)
		}
		return values, nil
	case *starlark.Dict:
		result := make(map[string]any, value.Len())
		for _, item := range value.Items() {
			key, ok := starlark.AsString(item[0])
			if !ok {
				return nil, fmt.Errorf("json.encode: got %s dict key, want string", item[0].Type())
			}
			converted, err := starlarkToJSON(item[1])
			if err != nil {
				return nil, err
			}
			result[key] = converted
		}
		return result, nil
	default:
		if attrs, ok := value.(starlark.HasAttrs); ok {
			attr, err := attrs.Attr("json")
			if err != nil {
				return nil, err
			}
			if attr != nil {
				return starlarkToJSON(attr)
			}
		}
		return nil, fmt.Errorf("json.encode: cannot encode %s", value.Type())
	}
}

func sortedDictKeys(dict *starlark.Dict) []string {
	keys := make([]string, 0, dict.Len())
	for _, item := range dict.Items() {
		if key, ok := starlark.AsString(item[0]); ok {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}

func compactJSON(value starlark.Value) string {
	native, err := starlarkToJSON(value)
	if err != nil {
		return fmt.Sprintf("<json error: %v>", err)
	}
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(native); err != nil {
		return fmt.Sprintf("<json error: %v>", err)
	}
	return stringsTrimTrailingNewline(buf.String())
}

func stringsTrimTrailingNewline(value string) string {
	return string(bytes.TrimSuffix([]byte(value), []byte("\n")))
}
