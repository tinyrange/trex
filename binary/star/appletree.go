package star

import (
	"bytes"
	"fmt"
	"github.com/tinyrange/trex/boot/darwin"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func appleDeviceTreeBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var file starlark.Value
	if err := starlark.UnpackArgs("apple_device_tree", args, kwargs, "file", &file); err != nil {
		return nil, err
	}
	r, ok := file.(storage.Reader)
	if !ok {
		return nil, fmt.Errorf("apple_device_tree: expected file")
	}
	n, err := darwin.DecodeNode(r)
	if err != nil {
		return nil, err
	}
	var convert func(darwin.Node) starlark.Value
	convert = func(n darwin.Node) starlark.Value {
		properties := starlark.NewDict(len(n.Properties))
		flags := starlark.NewDict(len(n.PropertyFlags))
		for k, v := range n.Properties {
			_ = properties.SetKey(starlark.String(k), starlark.Bytes(v))
		}
		for k, v := range n.PropertyFlags {
			_ = flags.SetKey(starlark.String(k), starlark.MakeUint(uint(v)))
		}
		children := make([]starlark.Value, len(n.Children))
		for i, c := range n.Children {
			children[i] = convert(c)
		}
		return starfile.NewRecord(starlark.StringDict{"properties": properties, "property_flags": flags, "children": starlark.NewList(children)})
	}
	return convert(n), nil
}

func encodeAppleDeviceTreeBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var tree starlark.Value
	if err := starlark.UnpackArgs("encode_apple_device_tree", args, kwargs, "tree", &tree); err != nil {
		return nil, err
	}
	nodes := 0
	var convert func(starlark.Value, int) (darwin.Node, error)
	convert = func(v starlark.Value, depth int) (darwin.Node, error) {
		nodes++
		n := darwin.Node{Properties: map[string][]byte{}, PropertyFlags: map[string]uint32{}}
		if depth > 32 || nodes > 4096 {
			return n, fmt.Errorf("apple device tree node limit")
		}
		a, attrs := v.(starlark.HasAttrs)
		mapping, dict := v.(*starlark.Dict)
		if !attrs && !dict {
			return n, fmt.Errorf("apple device tree: expected node record")
		}
		attr := func(name string) (starlark.Value, error) {
			if !dict {
				return a.Attr(name)
			}
			value, _, err := mapping.Get(starlark.String(name))
			return value, err
		}
		p, err := attr("properties")
		if err != nil {
			return n, err
		}
		props, ok := p.(*starlark.Dict)
		if !ok {
			return n, fmt.Errorf("apple device tree: expected property dictionary")
		}
		for _, kv := range props.Items() {
			k, ok := starlark.AsString(kv[0])
			if !ok {
				return n, fmt.Errorf("apple device tree: expected string key")
			}
			b, ok := kv[1].(starlark.Bytes)
			if !ok {
				return n, fmt.Errorf("apple device tree: expected property bytes")
			}
			n.Properties[k] = []byte(b)
		}
		f, err := attr("property_flags")
		if err != nil {
			return n, err
		}
		if f != nil && f != starlark.None {
			flags, ok := f.(*starlark.Dict)
			if !ok {
				return n, fmt.Errorf("apple device tree: expected flag dictionary")
			}
			for _, kv := range flags.Items() {
				k, ok := starlark.AsString(kv[0])
				if !ok {
					return n, fmt.Errorf("apple device tree: expected flag key")
				}
				var value uint32
				if err := starlark.AsInt(kv[1], &value); err != nil {
					return n, err
				}
				n.PropertyFlags[k] = value
			}
		}
		children, err := attr("children")
		if err != nil {
			return n, err
		}
		list, ok := children.(*starlark.List)
		if !ok {
			return n, fmt.Errorf("apple device tree: expected children list")
		}
		for i := 0; i < list.Len(); i++ {
			c, err := convert(list.Index(i), depth+1)
			if err != nil {
				return n, err
			}
			n.Children = append(n.Children, c)
		}
		return n, nil
	}
	n, err := convert(tree, 0)
	if err != nil {
		return nil, err
	}
	b, err := n.Encode()
	if err != nil {
		return nil, err
	}
	return starfile.NewReader("DeviceTree", bytes.NewReader(b)), nil
}
