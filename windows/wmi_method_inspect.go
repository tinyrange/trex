package windows

import (
	"encoding/binary"
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
	"unicode/utf16"
)

// inspectWMIMethods exposes original bounded method sections for diagnostics;
// it does not reinterpret or rewrite embedded parameter objects.
func inspectWMIMethods(raw []byte) ([]starlark.Value, error) {
	c := wmiObjectCursor{data: raw}
	n := c.u32()
	c.take(uint64(n) * 2)
	c.take(8)
	c.sized()
	part := c.sized()
	if c.err != nil {
		return nil, c.err
	}
	p := wmiObjectCursor{data: part}
	header := p.take(4)
	if p.err != nil {
		return nil, p.err
	}
	count := binary.LittleEndian.Uint16(header[:2])
	descriptors := p.take(uint64(count) * 24)
	heapSize := p.u32() & 0x7fffffff
	heap := p.take(uint64(heapSize))
	if p.err != nil {
		return nil, p.err
	}
	var result []starlark.Value
	for i := 0; i < int(count); i++ {
		d := descriptors[i*24 : (i+1)*24]
		name, err := wmiHeapString(heap, binary.LittleEndian.Uint32(d))
		if err != nil {
			return nil, err
		}
		fields := starlark.StringDict{"name": starlark.String(name), "flags": starlark.MakeUint64(uint64(binary.LittleEndian.Uint32(d[4:]))), "depth": starlark.MakeUint64(uint64(binary.LittleEndian.Uint32(d[8:])))}
		for j, field := range []string{"qualifiers", "input", "output"} {
			offset := binary.LittleEndian.Uint32(d[12+j*4:])
			if uint64(offset)+4 > uint64(len(heap)) {
				return nil, fmt.Errorf("wmi method %s: %s outside heap", name, field)
			}
			b := wmiObjectCursor{data: heap[offset:]}
			var body []byte
			if field == "qualifiers" {
				body = b.sized()
			} else {
				// Parameter-object lengths exclude their four-byte prefix; zero
				// denotes an absent input/output side. Qualifier sizes include it.
				n := b.u32()
				body = b.take(uint64(n))
			}
			if b.err != nil {
				return nil, b.err
			}
			if field == "qualifiers" {
				q, err := wmiDecodeQualifiers(body, heap)
				if err != nil {
					return nil, err
				}
				values := make([]starlark.Value, len(q))
				for k, v := range q {
					values[k] = mofQualifierValue(v)
				}
				fields[field] = starlark.NewList(values)
			} else {
				fields[field] = &starfile.Bytes{Name: name + "-" + field, Data: append([]byte(nil), body...)}
				layout, err := inspectWMIParameterObject(body)
				if err != nil {
					return nil, fmt.Errorf("wmi method %s %s: %w", name, field, err)
				}
				fields[field+"_layout"] = layout
			}
		}
		result = append(result, starfile.NewRecord(fields))
	}
	return result, nil
}

func (r *wmiRepositoryFile) methodSectionsBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var namespace, name string
	if err := starlark.UnpackArgs("method_sections", args, kwargs, "namespace", &namespace, "name", &name); err != nil {
		return nil, err
	}
	layout, err := r.classLayout(namespace, name)
	if err != nil {
		return nil, err
	}
	methods, err := inspectWMIMethods(layout.definition.raw)
	if err != nil {
		return nil, err
	}
	return starlark.NewList(methods), nil
}

func inspectWMIParameterObject(data []byte) (starlark.Value, error) {
	if len(data) == 0 {
		return starlark.None, nil
	}
	c := wmiObjectCursor{data: data}
	flag := c.take(1)
	if c.err != nil {
		return nil, c.err
	}
	if flag[0] != 1 && flag[0] != 5 {
		return nil, fmt.Errorf("unsupported embedded class flag %d", flag[0])
	}
	if flag[0] == 5 {
		for i := 0; i < 2; i++ {
			b := c.data[c.offset:]
			value, err := wmiHeapString(b, 0)
			if err != nil {
				return nil, err
			}
			n := len(value) + 2
			if b[0] == 1 {
				n = 1 + len(utf16.Encode([]rune(value)))*2 + 2
			}
			c.take(uint64(n))
			if c.err != nil {
				return nil, c.err
			}
		}
	}
	c.sized() // empty instance schema
	c.sized() // empty instance method table
	start := c.offset
	c.sized() // actual parameter class
	if c.err != nil {
		return nil, c.err
	}
	raw := make([]byte, 12)
	raw = append(raw, data[start:c.offset]...)
	decoded, err := decodeWMIClassRecord(raw)
	if err != nil {
		return nil, err
	}
	props := make([]starlark.Value, len(decoded.properties))
	for i, p := range decoded.properties {
		props[i] = starfile.NewRecord(starlark.StringDict{"property": mofFeatureValue(p.feature), "code": starlark.MakeUint64(uint64(p.code)), "index": starlark.MakeUint64(uint64(p.index)), "offset": starlark.MakeUint64(uint64(p.offset)), "depth": starlark.MakeUint64(uint64(p.depth))})
	}
	return starfile.NewRecord(starlark.StringDict{"name": starlark.String(decoded.class.Name), "properties": starlark.NewList(props), "qualifiers": mofQualifiersValue(decoded.class.Qualifiers), "default_states": starlark.String(fmt.Sprintf("%x", decoded.defaults)), "heap_bytes": starlark.MakeInt(len(decoded.heap))}), nil
}
