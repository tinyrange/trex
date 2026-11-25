package windows

import (
	"encoding/binary"
	"fmt"
	binaryapi "github.com/tinyrange/trex/binary"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
	"sort"
	"strings"
)

// readRegistry31 traverses only the reachable SHCC3.10 key tree. Hash buckets,
// free records and allocator slack are not keys. Values are unnamed strings;
// nil distinguishes an unset value from a present empty string.
func readRegistry31(data []byte) (map[string]*string, error) {
	if len(data) < 32 || len(data) > 1<<20 || string(data[:8]) != "SHCC3.10" {
		return nil, fmt.Errorf("registry31_entries: invalid SHCC3.10 header or size")
	}
	u32 := func(off int) uint64 { return uint64(binary.LittleEndian.Uint32(data[off:])) }
	table, count, text, size := u32(12), u32(16), u32(20), u32(24)
	if table < 32 || count < 2 || count > 65536 || table > uint64(len(data)) || count*8 > uint64(len(data))-table || text < table+count*8 || text > uint64(len(data)) || size > uint64(len(data))-text {
		return nil, fmt.Errorf("registry31_entries: invalid record/string bounds")
	}
	record := func(index uint16) ([4]uint16, error) {
		if uint64(index) >= count {
			return [4]uint16{}, fmt.Errorf("registry31_entries: record index outside table")
		}
		off := table + uint64(index)*8
		return [4]uint16{binary.LittleEndian.Uint16(data[off:]), binary.LittleEndian.Uint16(data[off+2:]), binary.LittleEndian.Uint16(data[off+4:]), binary.LittleEndian.Uint16(data[off+6:])}, nil
	}
	stringsUsed := map[uint16]bool{}
	stringAt := func(index uint16) (string, error) {
		if index == 0 {
			return "", fmt.Errorf("registry31_entries: missing string record")
		}
		rec, err := record(index)
		if err != nil {
			return "", err
		}
		off, n := uint64(rec[3]), uint64(rec[2])
		if off > size || n > size-off {
			return "", fmt.Errorf("registry31_entries: string outside arena")
		}
		raw := data[text+off : text+off+n]
		if strings.IndexByte(string(raw), 0) >= 0 {
			return "", fmt.Errorf("registry31_entries: embedded string NUL")
		}
		stringsUsed[index] = true
		return binaryapi.DecodeText(raw, "windows1252", false)
	}
	type pending struct {
		index  uint16
		parent string
		depth  int
	}
	root, _ := record(0)
	if root[1] == 0 {
		return map[string]*string{}, nil
	}
	stack := []pending{{index: root[1]}}
	visited := map[uint16]bool{}
	folded := map[string]bool{}
	out := map[string]*string{}
	pathBytes := 0
	for len(stack) > 0 {
		p := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if p.index == 0 {
			continue
		}
		if visited[p.index] || p.depth > 256 {
			return nil, fmt.Errorf("registry31_entries: cyclic/shared key or excessive depth")
		}
		visited[p.index] = true
		rec, err := record(p.index)
		if err != nil {
			return nil, err
		}
		name, err := stringAt(rec[2])
		if err != nil {
			return nil, err
		}
		if name == "" || strings.Contains(name, `\`) {
			return nil, fmt.Errorf("registry31_entries: invalid key component")
		}
		path := name
		if p.parent != "" {
			path = p.parent + `\` + name
		}
		pathBytes += len(path)
		if pathBytes > 16<<20 {
			return nil, fmt.Errorf("registry31_entries: path expansion exceeds limit")
		}
		fold := strings.ToLower(path)
		if folded[fold] {
			return nil, fmt.Errorf("registry31_entries: duplicate key path")
		}
		folded[fold] = true
		var value *string
		if rec[3] != 0 {
			v, err := stringAt(rec[3])
			if err != nil {
				return nil, err
			}
			value = &v
		}
		out[path] = value
		if rec[0] != 0 {
			stack = append(stack, pending{rec[0], p.parent, p.depth})
		}
		if rec[1] != 0 {
			stack = append(stack, pending{rec[1], path, p.depth + 1})
		}
	}
	for index := range visited {
		if stringsUsed[index] {
			return nil, fmt.Errorf("registry31_entries: key aliases a string record")
		}
	}
	return out, nil
}

func registry31EntriesBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("registry31_entries", args, kwargs, "file", &value); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("registry31_entries: got %s, want file", value.Type())
	}
	if file.Size() > 1<<20 {
		return nil, fmt.Errorf("registry31_entries: database exceeds 1 MiB inspection limit")
	}
	data, err := starfile.ReadAll(file)
	if err != nil {
		return nil, err
	}
	entries, err := readRegistry31(data)
	if err != nil {
		return nil, err
	}
	out := starlark.NewDict(len(entries))
	// Stable ordering is useful for inspection receipts.
	keys := make([]string, 0, len(entries))
	for key := range entries {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		var v starlark.Value = starlark.None
		if entries[key] != nil {
			v = starlark.String(*entries[key])
		}
		if err := out.SetKey(starlark.String(key), v); err != nil {
			return nil, err
		}
	}
	return out, nil
}
