package windows

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

type peStringEntry struct {
	id         uint32
	lang, text string
}

// Decode complete RT_STRING blocks without choosing a UI language or applying
// LoadString's caller-buffer truncation. Empty slots are absent; embedded NULs
// remain data. Unlike the legacy RGS heuristic, malformed resources are errors.
func peStringTableResources(resources []peResource) ([]peStringEntry, error) {
	var out []peStringEntry
	seen := map[string]bool{}
	for _, r := range resources {
		if r.typ != "#6" {
			continue
		}
		n, err := strconv.ParseUint(strings.TrimPrefix(r.name, "#"), 10, 32)
		if err != nil || r.name != "#"+strconv.FormatUint(n, 10) || n == 0 || n > 1<<28 {
			return nil, fmt.Errorf("invalid RT_STRING block %q", r.name)
		}
		key := r.name + ":" + r.lang
		if seen[key] {
			return nil, fmt.Errorf("duplicate RT_STRING block/language %s", key)
		}
		seen[key] = true
		if len(r.data) > 2<<20 {
			return nil, fmt.Errorf("RT_STRING block exceeds bound")
		}
		pos := 0
		for slot := uint32(0); slot < 16; slot++ {
			if len(r.data)-pos < 2 {
				return nil, fmt.Errorf("truncated RT_STRING length")
			}
			count := int(binary.LittleEndian.Uint16(r.data[pos:]))
			pos += 2
			if count > (len(r.data)-pos)/2 {
				return nil, fmt.Errorf("truncated RT_STRING text")
			}
			units := make([]uint16, count)
			for i := range units {
				units[i] = binary.LittleEndian.Uint16(r.data[pos+i*2:])
			}
			pos += count * 2
			// Avoid silently repairing ill-formed Unicode into different text.
			for i := 0; i < len(units); i++ {
				if units[i] >= 0xd800 && units[i] <= 0xdbff {
					if i+1 >= len(units) || units[i+1] < 0xdc00 || units[i+1] > 0xdfff {
						return nil, fmt.Errorf("invalid RT_STRING surrogate pair")
					}
					i++
				} else if units[i] >= 0xdc00 && units[i] <= 0xdfff {
					return nil, fmt.Errorf("unpaired RT_STRING surrogate")
				}
			}
			if count != 0 {
				out = append(out, peStringEntry{uint32((n-1)*16) + slot, r.lang, string(utf16.Decode(units))})
			}
		}
		// Resource size may include final DWORD padding, not arbitrary bytes.
		if len(r.data)-pos > 3 {
			return nil, fmt.Errorf("unexpected RT_STRING trailing data")
		}
		for _, b := range r.data[pos:] {
			if b != 0 {
				return nil, fmt.Errorf("nonzero RT_STRING padding")
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].id != out[j].id {
			return out[i].id < out[j].id
		}
		return out[i].lang < out[j].lang
	})
	return out, nil
}

func peStringsBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("pe.strings", args, kwargs, "file", &value); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("pe.strings requires a file")
	}
	data, err := peReadSnapshotData(file)
	if err != nil {
		return nil, err
	}
	resources, err := peResources(data)
	if err != nil {
		return nil, err
	}
	entries, err := peStringTableResources(resources)
	if err != nil {
		return nil, err
	}
	out := make([]starlark.Value, 0, len(entries))
	for _, e := range entries {
		out = append(out, starfile.NewRecord(map[string]starlark.Value{
			"id": starlark.MakeUint64(uint64(e.id)), "lang": starlark.String(e.lang), "text": starlark.String(e.text),
		}))
	}
	return starlark.NewList(out), nil
}
