// Package value contains reusable Starlark value adapters shared by optional
// frontends and protocol packages.
package value

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"sort"
	"strconv"
	"strings"

	"go.starlark.net/starlark"
)

// Starlark converts JSON-compatible native values to Starlark values. It is
// also useful for protocol event payloads that deliberately use the same
// portable data model.
func Starlark(value any) (starlark.Value, error) {
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
				return nil, fmt.Errorf("invalid number %q", text)
			}
			return starlark.MakeBigInt(integer), nil
		}
		floating, err := strconv.ParseFloat(text, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid number %q", text)
		}
		return starlark.Float(floating), nil
	case float64:
		return starlark.Float(value), nil
	case int:
		return starlark.MakeInt(value), nil
	case int64:
		return starlark.MakeInt64(value), nil
	case []any:
		items := make([]starlark.Value, len(value))
		for index, item := range value {
			converted, err := Starlark(item)
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
			converted, err := Starlark(value[key])
			if err != nil {
				return nil, err
			}
			if err := result.SetKey(starlark.String(key), converted); err != nil {
				return nil, err
			}
		}
		return result, nil
	default:
		return nil, fmt.Errorf("unsupported native value %T", value)
	}
}

func Native(value starlark.Value) (any, error) {
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
		if number, ok := value.Uint64(); ok {
			return number, nil
		}
		return value.String(), nil
	case starlark.Float:
		return float64(value), nil
	case *starlark.List:
		result := make([]any, value.Len())
		for index := range result {
			item, err := Native(value.Index(index))
			if err != nil {
				return nil, err
			}
			result[index] = item
		}
		return result, nil
	case *starlark.Dict:
		result := make(map[string]any, value.Len())
		for _, item := range value.Items() {
			key, ok := starlark.AsString(item[0])
			if !ok {
				return nil, fmt.Errorf("object key is %s, want string", item[0].Type())
			}
			decoded, err := Native(item[1])
			if err != nil {
				return nil, err
			}
			result[key] = decoded
		}
		return result, nil
	default:
		return nil, fmt.Errorf("cannot convert %s to a native value", value.Type())
	}
}

type Number float64

func (n *Number) Unpack(value starlark.Value) error {
	number, ok := starlark.AsFloat(value)
	if !ok || math.IsNaN(number) || math.IsInf(number, 0) {
		return fmt.Errorf("got %s, want finite int or float", value.Type())
	}
	*n = Number(number)
	return nil
}

type Record struct {
	Names  []string
	Values starlark.StringDict
}

func NewRecord(values starlark.StringDict) *Record {
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	return &Record{Names: names, Values: values}
}

func (r *Record) String() string { return "<record " + strings.Join(r.Names, ", ") + ">" }
func (r *Record) Type() string   { return "record" }
func (r *Record) Freeze() {
	for _, value := range r.Values {
		value.Freeze()
	}
}
func (r *Record) Truth() starlark.Bool                     { return starlark.True }
func (r *Record) Hash() (uint32, error)                    { return 0, fmt.Errorf("unhashable: %s", r.Type()) }
func (r *Record) Attr(name string) (starlark.Value, error) { return r.Values[name], nil }
func (r *Record) AttrNames() []string                      { return append([]string(nil), r.Names...) }
func (r *Record) Get(name string) starlark.Value           { return r.Values[name] }
