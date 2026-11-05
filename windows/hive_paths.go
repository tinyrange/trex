package windows

import (
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"

	"github.com/tinyrange/trex/windows/registry"
	"go.starlark.net/starlark"
)

// replaceRegistryPathComponents preserves all unmodified bytes, including
// terminators and malformed UTF-16 outside a matched component. NUL separates
// MULTI_SZ entries; backslash separates path components. Substrings never match.
func replaceRegistryPathComponents(raw []byte, replacements map[string][]byte) ([]byte, bool) {
	var out []byte
	start, copied := 0, 0
	for end := 0; end <= len(raw); end += 2 {
		terminal := end+1 >= len(raw)
		if !terminal {
			unit := binary.LittleEndian.Uint16(raw[end:])
			if unit != 0 && unit != 0x5c {
				continue
			}
		}
		stop := end
		if terminal {
			stop = len(raw)
		}
		if (stop-start)%2 == 0 {
			units := make([]uint16, (stop-start)/2)
			for i := range units {
				units[i] = binary.LittleEndian.Uint16(raw[start+2*i:])
			}
			if replacement, ok := replacements[strings.ToLower(string(utf16.Decode(units)))]; ok {
				out = append(out, raw[copied:start]...)
				out = append(out, replacement...)
				copied = stop
			}
		}
		start = end + 2
		if terminal {
			break
		}
	}
	if out == nil {
		return raw, false
	}
	out = append(out, raw[copied:]...)
	return out, true
}

func (h *registryHive) pathComponentPatches(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var mapping *starlark.Dict
	var excluded *starlark.List
	if err := starlark.UnpackArgs("hive.path_component_patches", args, kwargs, "replacements", &mapping, "exclude_keys?", &excluded); err != nil {
		return nil, err
	}
	if mapping.Len() > 65536 {
		return nil, fmt.Errorf("registry path replacement count exceeds bound")
	}
	replacements := make(map[string][]byte, mapping.Len())
	for _, item := range mapping.Items() {
		before, bok := starlark.AsString(item[0])
		after, aok := starlark.AsString(item[1])
		if !bok || !aok || before == "" || after == "" || strings.ContainsAny(before, "\\\x00") || strings.ContainsAny(after, "\\\x00") {
			return nil, fmt.Errorf("registry path replacements require nonempty literal components")
		}
		key := strings.ToLower(before)
		units := utf16.Encode([]rune(after))
		data := make([]byte, len(units)*2)
		for i, u := range units {
			binary.LittleEndian.PutUint16(data[i*2:], u)
		}
		if _, ok := replacements[key]; ok {
			return nil, fmt.Errorf("duplicate case-folded registry path component")
		}
		replacements[key] = data
	}
	exclusions := make(map[string]bool)
	if excluded != nil {
		if excluded.Len() > 65536 {
			return nil, fmt.Errorf("registry path exclusions exceed bound")
		}
		for i := 0; i < excluded.Len(); i++ {
			parts, err := registryPathParts(excluded.Index(i))
			if err != nil {
				return nil, err
			}
			// NUL cannot appear in a registry name, unlike slash.
			exclusions[strings.ToLower(strings.Join(parts, "\x00"))] = true
		}
	}
	reader, err := h.portableReader()
	if err != nil {
		return nil, err
	}
	root, err := reader.ReadKey(reader.RootCell())
	if err != nil {
		return nil, err
	}
	type pending struct {
		key   registry.Key
		parts []string
	}
	stack := []pending{{key: root}}
	visited := make(map[uint32]bool)
	results := starlark.NewList(nil)
	values, totalBytes := 0, 0
	for len(stack) > 0 {
		current := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if exclusions[strings.ToLower(strings.Join(current.parts, "\x00"))] {
			continue
		}
		if visited[current.key.Cell] || len(visited) >= 1<<20 || len(current.parts) > 512 {
			return nil, fmt.Errorf("registry traversal cycle or bound exceeded")
		}
		visited[current.key.Cell] = true
		cells, err := reader.ValueCells(current.key)
		if err != nil {
			return nil, err
		}
		for _, cell := range cells {
			values++
			if values > 1<<22 {
				return nil, fmt.Errorf("registry value traversal exceeds bound")
			}
			value, err := reader.ReadValue(cell)
			if err != nil {
				return nil, err
			}
			if value.Type != 1 && value.Type != 2 && value.Type != 7 {
				continue
			}
			totalBytes += len(value.Data)
			if totalBytes > 1<<30 {
				return nil, fmt.Errorf("registry string traversal exceeds bound")
			}
			data, changed := replaceRegistryPathComponents(value.Data, replacements)
			if !changed {
				continue
			}
			if results.Len() >= 65536 {
				return nil, fmt.Errorf("registry path patch count exceeds bound")
			}
			parts := make([]starlark.Value, len(current.parts))
			for i, p := range current.parts {
				parts[i] = starlark.String(p)
			}
			patch := starlark.NewDict(5)
			patch.SetKey(starlark.String("key_parts"), starlark.NewList(parts))
			patch.SetKey(starlark.String("name"), starlark.String(value.Name))
			patch.SetKey(starlark.String("type"), starlark.MakeUint64(uint64(value.Type)))
			patch.SetKey(starlark.String("value"), starlark.Bytes(data))
			patch.SetKey(starlark.String("before"), starlark.Bytes(value.Data))
			results.Append(patch)
		}
		children, err := reader.ReadSubkeys(current.key)
		if err != nil {
			return nil, err
		}
		for i := len(children) - 1; i >= 0; i-- {
			parts := append(append([]string(nil), current.parts...), children[i].Name)
			stack = append(stack, pending{key: children[i], parts: parts})
		}
	}
	return results, nil
}
