package windows

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strings"

	"go.starlark.net/starlark"
)

// EventTemplateProviders reads the bounded CRIM 5.1 provider directory from a
// WEVT_TEMPLATE resource. It validates the directory and non-overlapping WEVT
// block extents, not event schemas, message IDs, channels, or executable code.
func EventTemplateProviders(data []byte) ([]string, error) {
	if len(data) < 16 || len(data) > 16<<20 || string(data[:4]) != "CRIM" {
		return nil, fmt.Errorf("invalid event template header")
	}
	size := uint64(binary.LittleEndian.Uint32(data[4:]))
	count := uint64(binary.LittleEndian.Uint32(data[12:]))
	if binary.LittleEndian.Uint16(data[8:]) != 5 || binary.LittleEndian.Uint16(data[10:]) != 1 {
		return nil, fmt.Errorf("unsupported event template version")
	}
	if size < 16 || size > uint64(len(data)) || uint64(len(data))-size > 3 || count > (size-16)/20 {
		return nil, fmt.Errorf("event template directory exceeds extent")
	}
	for _, b := range data[size:] {
		if b != 0 {
			return nil, fmt.Errorf("nonzero event template padding")
		}
	}
	type extent struct{ start, end uint64 }
	extents := make([]extent, 0, count)
	result := make([]string, 0, count)
	seen := make(map[[16]byte]bool)
	for i := uint64(0); i < count; i++ {
		row := data[16+i*20 : 16+(i+1)*20]
		var guid [16]byte
		copy(guid[:], row[:16])
		if guid == [16]byte{} || seen[guid] {
			return nil, fmt.Errorf("duplicate or empty event provider GUID")
		}
		seen[guid] = true
		offset := uint64(binary.LittleEndian.Uint32(row[16:]))
		if offset < 16+count*20 || offset > size || size-offset < 20 || offset%4 != 0 || string(data[offset:offset+4]) != "WEVT" {
			return nil, fmt.Errorf("invalid event provider block")
		}
		length := uint64(binary.LittleEndian.Uint32(data[offset+4:]))
		if length < 20 || length > size-offset {
			return nil, fmt.Errorf("event provider block exceeds extent")
		}
		extents = append(extents, extent{offset, offset + length})
		result = append(result, strings.ToLower(windowsGUIDString(guid)))
	}
	sort.Slice(extents, func(i, j int) bool { return extents[i].start < extents[j].start })
	for i := 1; i < len(extents); i++ {
		if extents[i].start < extents[i-1].end {
			return nil, fmt.Errorf("overlapping event provider blocks")
		}
	}
	return result, nil
}

func eventTemplateProvidersBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var source starlark.Value
	if err := starlark.UnpackArgs("event_template_providers", args, kwargs, "source", &source); err != nil {
		return nil, err
	}
	data, err := bytesForBinaryValueLimited(source, 16<<20)
	if err != nil {
		return nil, err
	}
	providers, err := EventTemplateProviders(data)
	if err != nil {
		return nil, err
	}
	values := make([]starlark.Value, len(providers))
	for i, p := range providers {
		values[i] = starlark.String(p)
	}
	return starlark.NewList(values), nil
}
