package windows

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strings"

	binaryapi "github.com/tinyrange/trex/binary"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

// registry31Builtin constructs the Win3.1 SHCC database, whose keys have one
// unnamed string value. Inputs and output are portable; no registry API or
// guest utility participates in construction.
func registry31Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var entries *starlark.Dict
	var sources *starlark.List
	if err := starlark.UnpackArgs("registry31", args, kwargs, "entries", &entries, "sources?", &sources); err != nil {
		return nil, err
	}
	values := map[string]string{}
	if sources != nil {
		for i := 0; i < sources.Len(); i++ {
			f, ok := sources.Index(i).(starfile.File)
			if !ok {
				return nil, fmt.Errorf("registry31: sources must be files")
			}
			if f.Size() > 1<<20 {
				return nil, fmt.Errorf("registry31: registration source exceeds limit")
			}
			b, err := starfile.ReadAll(f)
			if err != nil {
				return nil, err
			}
			s, err := binaryapi.DecodeText(b, "windows1252", false)
			if err != nil {
				return nil, err
			}
			for _, line := range strings.Split(s, "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.EqualFold(line, "REGEDIT") || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "//") {
					continue
				}
				key, value, found := strings.Cut(line, "=")
				key = strings.TrimSpace(key)
				const prefix = `HKEY_CLASSES_ROOT\`
				if !strings.HasPrefix(strings.ToUpper(key), prefix) {
					continue // REGEDIT 3.1 treats all other lines as comments.
				}
				if !found {
					value = ""
				}
				values[strings.ToLower(key[len(prefix):])] = strings.TrimSpace(value)
			}
		}
	}
	for _, pair := range entries.Items() {
		k, ok := starlark.AsString(pair[0])
		v, valid := starlark.AsString(pair[1])
		if !ok || !valid {
			return nil, fmt.Errorf("registry31: entries must map class paths to strings")
		}
		values[strings.ToLower(k)] = v
	}
	data, err := buildRegistry31(values)
	if err != nil {
		return nil, err
	}
	return &starfile.Bytes{Data: data}, nil
}

type registry31Node struct {
	name, value string
	hasValue    bool
	children    map[string]*registry31Node
	index       uint16
}

func buildRegistry31(values map[string]string) ([]byte, error) {
	root := &registry31Node{name: ".classes", children: map[string]*registry31Node{}}
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if key == "" || strings.ContainsRune(key, 0) {
			return nil, fmt.Errorf("registry31: invalid class path")
		}
		node := root
		for _, part := range strings.Split(key, `\`) {
			if part == "" {
				return nil, fmt.Errorf("registry31: empty path component")
			}
			fold := strings.ToLower(part)
			next := node.children[fold]
			if next == nil {
				next = &registry31Node{name: part, children: map[string]*registry31Node{}}
				node.children[fold] = next
			}
			node = next
		}
		node.value, node.hasValue = values[key], true
	}
	// One bucket is a valid hash table and places every interned string in one
	// circular chain. It avoids depending on the undocumented string hash.
	table := [][4]uint16{{}, {1, 0, 0, 0}}
	text := []byte{0}
	interned := map[string]uint16{}
	addString := func(s string) (uint16, error) {
		if strings.ContainsRune(s, 0) {
			return 0, fmt.Errorf("registry31: embedded NUL")
		}
		if idx, ok := interned[s]; ok {
			table[idx][1]++
			return idx, nil
		}
		b, err := binaryapi.EncodeText(s, "windows1252", false)
		if err != nil {
			return 0, err
		}
		if len(text)+len(b)+2 > 65535 || len(table) >= 32767 {
			return 0, fmt.Errorf("registry31: database exceeds 16-bit limits")
		}
		idx := uint16(len(table))
		off := len(text) + 2
		text = binary.LittleEndian.AppendUint16(text, idx*2+1)
		text = append(text, b...)
		table = append(table, [4]uint16{table[1][0], 1, uint16(len(b)), uint16(off)})
		table[1][0] = idx
		interned[s] = idx
		return idx, nil
	}
	var emit func(*registry31Node) (uint16, error)
	emit = func(n *registry31Node) (uint16, error) {
		if len(table) >= 32767 {
			return 0, fmt.Errorf("registry31: too many records")
		}
		idx := uint16(len(table))
		table = append(table, [4]uint16{})
		n.index = idx
		name, err := addString(n.name)
		if err != nil {
			return 0, err
		}
		table[idx][2] = name
		if n.hasValue {
			v, err := addString(n.value)
			if err != nil {
				return 0, err
			}
			table[idx][3] = v
		}
		names := make([]string, 0, len(n.children))
		for name := range n.children {
			names = append(names, name)
		}
		sort.Strings(names)
		var prev uint16
		for _, name := range names {
			child, err := emit(n.children[name])
			if err != nil {
				return 0, err
			}
			if prev == 0 {
				table[idx][1] = child
			} else {
				table[prev][0] = child
			}
			prev = child
		}
		return idx, nil
	}
	idx, err := emit(root)
	if err != nil {
		return nil, err
	}
	table[0][1] = idx
	if 32+len(table)*8+len(text) > 65535 {
		return nil, fmt.Errorf("registry31: database exceeds 64 KiB")
	}
	data := make([]byte, 32)
	copy(data, "SHCC3.10")
	binary.LittleEndian.PutUint32(data[8:], 32)
	binary.LittleEndian.PutUint32(data[12:], 32)
	binary.LittleEndian.PutUint32(data[16:], uint32(len(table)))
	binary.LittleEndian.PutUint32(data[20:], uint32(32+8*len(table)))
	binary.LittleEndian.PutUint32(data[24:], uint32(len(text)))
	binary.LittleEndian.PutUint16(data[28:], 1)
	for _, entry := range table {
		for _, word := range entry {
			data = binary.LittleEndian.AppendUint16(data, word)
		}
	}
	return append(data, text...), nil
}
