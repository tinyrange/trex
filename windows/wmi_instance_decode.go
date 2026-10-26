package windows

import (
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
	"strconv"
	"strings"
)

func decodeWMIModernInstance(raw []byte, layout *wmiClassLayout) (map[string]mofValue, error) {
	c := wmiObjectCursor{data: raw}
	hashRaw := c.take(128)
	c.take(16)
	body := c.sized()
	if c.err != nil {
		return nil, c.err
	}
	hash, err := wmiDecodeUTF16(hashRaw)
	if err != nil {
		return nil, err
	}
	if hash != wmiUpperUTF16SHA256(layout.definition.class.Name) {
		return nil, fmt.Errorf("wmi object: instance class hash mismatch")
	}
	p := wmiObjectCursor{data: body}
	nameOffset := p.u32()
	p.take(1)
	states := p.take(uint64((len(layout.properties)*2 + 7) / 8))
	size := uint64(0)
	for _, prop := range layout.properties {
		_, n, err := wmiDecodeType(prop.code)
		if err != nil {
			return nil, err
		}
		size += uint64(n)
	}
	values := p.take(size)
	p.sized()
	dyn := p.take(1)
	if p.err != nil {
		return nil, p.err
	}
	if dyn[0] != 1 {
		return nil, fmt.Errorf("wmi object: dynamic instance qualifiers not supported")
	}
	heapSize := p.u32() & 0x7fffffff
	heap := p.take(uint64(heapSize))
	if p.err != nil {
		return nil, p.err
	}
	name, err := wmiHeapString(heap, nameOffset)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(name, layout.definition.class.Name) {
		return nil, fmt.Errorf("wmi object: instance class name mismatch")
	}
	result := map[string]mofValue{}
	for i, prop := range layout.properties {
		state := (states[i/4] >> uint(i%4*2)) & 3
		value := mofValue{Kind: mofValueNull}
		if state&1 == 0 {
			if state&2 != 0 {
				if prop.feature.Value != nil {
					value = *prop.feature.Value
				}
			} else {
				if uint64(prop.offset) >= uint64(len(values)) {
					return nil, fmt.Errorf("wmi object: invalid instance property offset")
				}
				value, err = wmiDecodeValue(values[prop.offset:], heap, prop.code)
				if err != nil {
					return nil, err
				}
			}
		}
		result[prop.feature.Name] = value
	}
	return result, nil
}
func (r *wmiRepositoryFile) instancesBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var namespace, name string
	if err := starlark.UnpackArgs("instances", args, kwargs, "namespace", &namespace, "name", &name); err != nil {
		return nil, err
	}
	layout, err := r.classLayout(namespace, name)
	if err != nil {
		return nil, err
	}
	records := map[[2]uint32]wmiRepositoryRecord{}
	for _, rec := range r.records {
		records[[2]uint32{rec.logicalPage, rec.id}] = rec
	}
	prefix := "NS_" + wmiUpperUTF16SHA256(normalizeWMINamespace(namespace, `ROOT\CIMV2`)) + `\CI_` + wmiUpperUTF16SHA256(name) + `\IL_`
	var results []starlark.Value
	for _, page := range r.pages {
		for _, key := range page.keys {
			if strings.HasPrefix(key, prefix) {
				parts := strings.Split(key, ".")
				p, _ := strconv.ParseUint(parts[1], 10, 32)
				id, _ := strconv.ParseUint(parts[2], 10, 32)
				rec := records[[2]uint32{uint32(p), uint32(id)}]
				values, err := decodeWMIModernInstance(rec.data, layout)
				if err != nil {
					return nil, fmt.Errorf("instance %s: %w", key, err)
				}
				dict := starlark.NewDict(len(values))
				for name, value := range values {
					dict.SetKey(starlark.String(name), mofValueValue(value))
				}
				results = append(results, starfile.NewRecord(starlark.StringDict{"key": starlark.String(key), "properties": dict}))
			}
		}
	}
	return starlark.NewList(results), nil
}
