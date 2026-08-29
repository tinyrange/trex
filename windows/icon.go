package windows

import (
	"encoding/binary"
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"math"

	"go.starlark.net/starlark"
)

type windowsIconImage struct {
	data         []byte
	resourceID   uint16
	resourceType uint16
	index        int
	width        int
	height       int
	bitsPerPixel uint16
}

type windowsIconDirectoryEntry struct {
	width        int
	height       int
	bitsPerPixel uint16
	size         uint32
	offset       uint32
	resourceID   uint16
}

func windowsIconBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	index, width, height := 0, 32, 32
	if err := starlark.UnpackArgs(
		"icon", args, kwargs,
		"file", &value,
		"index?", &index,
		"width?", &width,
		"height?", &height,
	); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("icon: got %s, want file", value.Type())
	}
	if index < 0 {
		return nil, fmt.Errorf("icon: index must be non-negative")
	}
	if width <= 0 || height <= 0 {
		return nil, fmt.Errorf("icon: width and height must be positive")
	}
	data, err := starfile.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("icon: %w", err)
	}
	image, err := windowsIcon(data, index, width, height)
	if err != nil {
		return nil, fmt.Errorf("icon: %w", err)
	}
	return starfile.NewRecord(map[string]starlark.Value{
		"bits_per_pixel": starlark.MakeInt(int(image.bitsPerPixel)),
		"data":           starlark.Bytes(image.data),
		"height":         starlark.MakeInt(image.height),
		"index":          starlark.MakeInt(image.index),
		"resource_id":    starlark.MakeInt(int(image.resourceID)),
		"resource_type":  starlark.MakeInt(int(image.resourceType)),
		"width":          starlark.MakeInt(image.width),
	}), nil
}

func windowsIcon(data []byte, index, width, height int) (windowsIconImage, error) {
	if len(data) >= 4 && binary.LittleEndian.Uint32(data[:4]) == 0x00010000 {
		return windowsIconFromICO(data, index, width, height)
	}
	if len(data) < 0x40 || data[0] != 'M' || data[1] != 'Z' {
		return windowsIconImage{}, fmt.Errorf("unsupported executable or icon format")
	}
	header := int(binary.LittleEndian.Uint32(data[0x3c:0x40]))
	if header < 0 || header+2 > len(data) {
		return windowsIconImage{}, fmt.Errorf("executable header outside file")
	}
	var resources []peResource
	var err error
	switch string(data[header : header+2]) {
	case "PE":
		resources, err = peResources(data)
	case "NE":
		resources, err = neResources(data, header)
	default:
		return windowsIconImage{}, fmt.Errorf("unsupported executable signature %q", data[header:header+2])
	}
	if err != nil {
		return windowsIconImage{}, err
	}
	return windowsIconFromResources(resources, index, width, height)
}

func windowsIconFromICO(data []byte, index, width, height int) (windowsIconImage, error) {
	entries, err := parseICODirectory(data)
	if err != nil {
		return windowsIconImage{}, err
	}
	if index >= len(entries) {
		return windowsIconImage{}, fmt.Errorf("icon index %d outside %d images", index, len(entries))
	}
	// An ICO index names an image directly. Width and height only disambiguate
	// executable icon groups, where one logical icon has several image sizes.
	entry := entries[index]
	end := uint64(entry.offset) + uint64(entry.size)
	if end > uint64(len(data)) {
		return windowsIconImage{}, fmt.Errorf("icon image outside file")
	}
	return windowsIconImage{
		data:         append([]byte(nil), data[entry.offset:uint32(end)]...),
		resourceType: 3,
		index:        index,
		width:        entry.width,
		height:       entry.height,
		bitsPerPixel: entry.bitsPerPixel,
	}, nil
}

func windowsIconFromResources(resources []peResource, index, width, height int) (windowsIconImage, error) {
	groups := make([]peResource, 0)
	seen := make(map[string]bool)
	for _, resource := range resources {
		if resource.typ == "#14" && !seen[resource.name] {
			seen[resource.name] = true
			groups = append(groups, resource)
		}
	}
	if index >= len(groups) {
		return windowsIconImage{}, fmt.Errorf("icon index %d outside %d groups", index, len(groups))
	}
	group := groups[index]
	entries, err := parseGroupIconDirectory(group.data)
	if err != nil {
		return windowsIconImage{}, fmt.Errorf("group %s: %w", group.name, err)
	}
	entry := closestIconEntry(entries, width, height)
	wantedName := fmt.Sprintf("#%d", entry.resourceID)
	var fallback *peResource
	for resourceIndex := range resources {
		resource := &resources[resourceIndex]
		if resource.typ != "#3" || resource.name != wantedName {
			continue
		}
		if resource.lang == group.lang {
			fallback = resource
			break
		}
		if fallback == nil {
			fallback = resource
		}
	}
	if fallback == nil {
		return windowsIconImage{}, fmt.Errorf("group %s references missing icon resource %d", group.name, entry.resourceID)
	}
	if uint64(entry.size) > uint64(len(fallback.data)) {
		return windowsIconImage{}, fmt.Errorf("icon resource %d is shorter than its group entry", entry.resourceID)
	}
	return windowsIconImage{
		data:         append([]byte(nil), fallback.data[:entry.size]...),
		resourceID:   entry.resourceID,
		resourceType: 3,
		index:        index,
		width:        entry.width,
		height:       entry.height,
		bitsPerPixel: entry.bitsPerPixel,
	}, nil
}

func parseICODirectory(data []byte) ([]windowsIconDirectoryEntry, error) {
	if len(data) < 6 || binary.LittleEndian.Uint16(data[:2]) != 0 || binary.LittleEndian.Uint16(data[2:4]) != 1 {
		return nil, fmt.Errorf("invalid ICO header")
	}
	count := int(binary.LittleEndian.Uint16(data[4:6]))
	if count == 0 || count > (len(data)-6)/16 {
		return nil, fmt.Errorf("invalid ICO image count %d", count)
	}
	entries := make([]windowsIconDirectoryEntry, 0, count)
	for i := 0; i < count; i++ {
		offset := 6 + i*16
		entries = append(entries, windowsIconDirectoryEntry{
			width:        iconDimension(data[offset]),
			height:       iconDimension(data[offset+1]),
			bitsPerPixel: binary.LittleEndian.Uint16(data[offset+6 : offset+8]),
			size:         binary.LittleEndian.Uint32(data[offset+8 : offset+12]),
			offset:       binary.LittleEndian.Uint32(data[offset+12 : offset+16]),
		})
	}
	return entries, nil
}

func parseGroupIconDirectory(data []byte) ([]windowsIconDirectoryEntry, error) {
	if len(data) < 6 || binary.LittleEndian.Uint16(data[:2]) != 0 || binary.LittleEndian.Uint16(data[2:4]) != 1 {
		return nil, fmt.Errorf("invalid group icon header")
	}
	count := int(binary.LittleEndian.Uint16(data[4:6]))
	if count == 0 || count > (len(data)-6)/14 {
		return nil, fmt.Errorf("invalid group icon image count %d", count)
	}
	entries := make([]windowsIconDirectoryEntry, 0, count)
	for i := 0; i < count; i++ {
		offset := 6 + i*14
		entries = append(entries, windowsIconDirectoryEntry{
			width:        iconDimension(data[offset]),
			height:       iconDimension(data[offset+1]),
			bitsPerPixel: binary.LittleEndian.Uint16(data[offset+6 : offset+8]),
			size:         binary.LittleEndian.Uint32(data[offset+8 : offset+12]),
			resourceID:   binary.LittleEndian.Uint16(data[offset+12 : offset+14]),
		})
	}
	return entries, nil
}

func closestIconEntry(entries []windowsIconDirectoryEntry, width, height int) windowsIconDirectoryEntry {
	best := entries[0]
	bestDistance := math.MaxInt
	for _, entry := range entries {
		distance := absInt(entry.width-width) + absInt(entry.height-height)
		if distance < bestDistance || (distance == bestDistance && entry.bitsPerPixel > best.bitsPerPixel) {
			best, bestDistance = entry, distance
		}
	}
	return best
}

func iconDimension(value byte) int {
	if value == 0 {
		return 256
	}
	return int(value)
}

func absInt(value int) int {
	if value < 0 {
		return -value
	}
	return value
}

func neResources(data []byte, header int) ([]peResource, error) {
	if header < 0 || header+0x28 > len(data) {
		return nil, fmt.Errorf("NE header outside file")
	}
	resourceTable := header + int(binary.LittleEndian.Uint16(data[header+0x24:header+0x26]))
	residentNames := header + int(binary.LittleEndian.Uint16(data[header+0x26:header+0x28]))
	if resourceTable < header || resourceTable+2 > len(data) || residentNames < resourceTable || residentNames > len(data) {
		return nil, fmt.Errorf("NE resource table outside file")
	}
	shift := uint(binary.LittleEndian.Uint16(data[resourceTable : resourceTable+2]))
	if shift > 31 {
		return nil, fmt.Errorf("invalid NE resource alignment shift %d", shift)
	}
	resourceName := func(raw uint16) (string, error) {
		if raw&0x8000 != 0 {
			return fmt.Sprintf("#%d", raw&0x7fff), nil
		}
		offset := resourceTable + int(raw)
		if offset < resourceTable || offset >= residentNames {
			return "", fmt.Errorf("NE resource name outside table")
		}
		length := int(data[offset])
		if offset+1+length > residentNames {
			return "", fmt.Errorf("NE resource name outside table")
		}
		return string(data[offset+1 : offset+1+length]), nil
	}

	var resources []peResource
	cursor := resourceTable + 2
	for {
		if cursor+2 > residentNames {
			return nil, fmt.Errorf("unterminated NE resource table")
		}
		typeRaw := binary.LittleEndian.Uint16(data[cursor : cursor+2])
		if typeRaw == 0 {
			break
		}
		if cursor+8 > residentNames {
			return nil, fmt.Errorf("NE resource type outside table")
		}
		count := int(binary.LittleEndian.Uint16(data[cursor+2 : cursor+4]))
		typ, err := resourceName(typeRaw)
		if err != nil {
			return nil, err
		}
		cursor += 8
		if count > (residentNames-cursor)/12 {
			return nil, fmt.Errorf("NE resource entries outside table")
		}
		for i := 0; i < count; i++ {
			offsetUnits := binary.LittleEndian.Uint16(data[cursor : cursor+2])
			lengthUnits := binary.LittleEndian.Uint16(data[cursor+2 : cursor+4])
			nameRaw := binary.LittleEndian.Uint16(data[cursor+6 : cursor+8])
			name, err := resourceName(nameRaw)
			if err != nil {
				return nil, err
			}
			offset64 := uint64(offsetUnits) << shift
			length64 := uint64(lengthUnits) << shift
			if offset64+length64 > uint64(len(data)) {
				return nil, fmt.Errorf("NE resource %s/%s outside file", typ, name)
			}
			resources = append(resources, peResource{
				typ:  typ,
				name: name,
				data: append([]byte(nil), data[offset64:offset64+length64]...),
			})
			cursor += 12
		}
	}
	return resources, nil
}
