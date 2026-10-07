package star

import (
	"bytes"
	"fmt"
	"sort"

	"github.com/tinyrange/trex/binary/plist"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

type plistDate struct{ value plist.Date }

func (d *plistDate) String() string {
	return fmt.Sprintf("plist_date(%q)", d.value.Format("2006-01-02T15:04:05.999999999Z07:00"))
}
func (d *plistDate) Type() string          { return "plist_date" }
func (d *plistDate) Freeze()               {}
func (d *plistDate) Truth() starlark.Bool  { return true }
func (d *plistDate) Hash() (uint32, error) { return starlark.String(d.String()).Hash() }

func plistBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("plist", args, kwargs, "source", &value); err != nil {
		return nil, err
	}
	view, err := newBinaryByteView(value)
	if err != nil {
		return nil, err
	}
	if view.size > plist.MaxBytes {
		return nil, fmt.Errorf("plist: input size limit")
	}
	raw := make([]byte, int(view.size))
	if _, err = view.ReadAt(raw, 0); err != nil {
		return nil, err
	}
	result, err := plist.Decode(raw)
	if err != nil {
		return nil, err
	}
	return plistValue(result)
}
func plistValue(value any) (starlark.Value, error) {
	switch x := value.(type) {
	case nil:
		return starlark.None, nil
	case bool:
		return starlark.Bool(x), nil
	case string:
		return starlark.String(x), nil
	case []byte:
		return starlark.Bytes(x), nil
	case int64:
		return starlark.MakeInt64(x), nil
	case float64:
		return starlark.Float(x), nil
	case plist.Date:
		return &plistDate{value: x}, nil
	case []any:
		items := make([]starlark.Value, len(x))
		for i, v := range x {
			item, err := plistValue(v)
			if err != nil {
				return nil, err
			}
			items[i] = item
		}
		return starlark.NewList(items), nil
	case map[string]any:
		d := starlark.NewDict(len(x))
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			v, err := plistValue(x[k])
			if err != nil {
				return nil, err
			}
			if err = d.SetKey(starlark.String(k), v); err != nil {
				return nil, err
			}
		}
		return d, nil
	default:
		return nil, fmt.Errorf("plist: unsupported value %T", value)
	}
}

type plistBudget struct{ nodes, bytes int }

func (b *plistBudget) use(size int) error {
	if size > plist.MaxBytes-b.bytes {
		return fmt.Errorf("plist_encode: byte limit")
	}
	b.bytes += size
	return nil
}
func plistNative(value starlark.Value, depth int, budget *plistBudget) (any, error) {
	budget.nodes++
	if depth > 128 || budget.nodes > 100000 {
		return nil, fmt.Errorf("plist_encode: value limit")
	}
	switch x := value.(type) {
	case starlark.Bool:
		return bool(x), nil
	case starlark.String:
		if err := budget.use(len(x)); err != nil {
			return nil, err
		}
		return string(x), nil
	case starlark.Bytes:
		if err := budget.use(len(x)); err != nil {
			return nil, err
		}
		return []byte(x), nil
	case starlark.Int:
		n, ok := x.Int64()
		if !ok {
			return nil, fmt.Errorf("plist_encode: integer exceeds int64")
		}
		return n, nil
	case starlark.Float:
		return float64(x), nil
	case *plistDate:
		return x.value, nil
	case *starlark.List:
		if x.Len() > 100000-budget.nodes {
			return nil, fmt.Errorf("plist_encode: value limit")
		}
		items := make([]any, x.Len())
		for i := range items {
			v, err := plistNative(x.Index(i), depth+1, budget)
			if err != nil {
				return nil, err
			}
			items[i] = v
		}
		return items, nil
	case starlark.Tuple:
		if len(x) > 100000-budget.nodes {
			return nil, fmt.Errorf("plist_encode: value limit")
		}
		items := make([]any, len(x))
		for i, v := range x {
			converted, err := plistNative(v, depth+1, budget)
			if err != nil {
				return nil, err
			}
			items[i] = converted
		}
		return items, nil
	case *starlark.Dict:
		if x.Len() > (100000-budget.nodes)/2 {
			return nil, fmt.Errorf("plist_encode: value limit")
		}
		d := make(map[string]any, x.Len())
		for _, item := range x.Items() {
			k, ok := starlark.AsString(item[0])
			if !ok {
				return nil, fmt.Errorf("plist_encode: key must be string")
			}
			budget.nodes++
			if err := budget.use(len(k)); err != nil {
				return nil, err
			}
			v, err := plistNative(item[1], depth+1, budget)
			if err != nil {
				return nil, err
			}
			d[k] = v
		}
		return d, nil
	default:
		return nil, fmt.Errorf("plist_encode: unsupported %s", value.Type())
	}
}
func plistEncodeBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("plist_encode", args, kwargs, "value", &value); err != nil {
		return nil, err
	}
	budget := plistBudget{}
	native, err := plistNative(value, 0, &budget)
	if err != nil {
		return nil, err
	}
	raw, err := plist.EncodeXML(native)
	if err != nil {
		return nil, err
	}
	return starfile.NewReader("plist.xml", bytes.NewReader(raw)), nil
}
