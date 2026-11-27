package lab

import (
	"encoding/binary"
	"fmt"
	"math"
	"strings"

	"go.starlark.net/starlark"
	"golang.org/x/text/encoding/charmap"
)

const (
	groupHeaderSize = 34
	groupItemSize   = 24
	groupIconSize   = 32
)

type programItem struct {
	name, command, iconPath string
	iconIndex               int
	icon                    []byte
}

func programGroupBuiltin(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	var entries *starlark.List
	var index int
	var visible bool
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "name", &name, "items", &entries, "index", &index, "visible", &visible); err != nil {
		return nil, err
	}
	items := make([]programItem, 0, entries.Len())
	for i := range entries.Len() {
		entry, ok := entries.Index(i).(starlark.Tuple)
		if !ok {
			return nil, fmt.Errorf("program item %d must be a tuple", i+1)
		}
		var item programItem
		var icon starlark.Bytes
		if err := starlark.UnpackPositionalArgs(b.Name(), entry, nil, 5, &item.name, &item.command, &item.iconPath, &item.iconIndex, &icon); err != nil {
			return nil, err
		}
		item.icon = []byte(icon)
		items = append(items, item)
	}
	data, err := encodeProgramGroup(name, items, index, visible)
	if err != nil {
		return nil, err
	}
	return starlark.Bytes(data), nil
}

// encodeProgramGroup writes the Windows 3.1 PMCC file layout. Its coordinates
// and offsets are 16-bit and its icons use DDB masks, unlike NT PMCC groups.
// See the Windows 3.1 SDK Programmer's Reference, ch. 5, and Microsoft Q86334.
func encodeProgramGroup(name string, items []programItem, index int, visible bool) ([]byte, error) {
	if len(items) == 0 || len(items) > 50 || index < 0 || index >= 40 {
		return nil, fmt.Errorf("Windows 3.1 program group exceeds the shell limits")
	}
	data := make([]byte, groupHeaderSize+2*len(items))
	copy(data, "PMCC")
	put := func(offset int, value uint16) { binary.LittleEndian.PutUint16(data[offset:], value) }
	text := func(value string) (uint16, error) {
		if value == "" || strings.ContainsRune(value, 0) {
			return 0, fmt.Errorf("invalid program group string %q", value)
		}
		encoded, err := charmap.Windows1252.NewEncoder().String(value)
		if err != nil {
			return 0, err
		}
		if len(data)+len(encoded)+1 > math.MaxUint16 {
			return 0, fmt.Errorf("program group exceeds a 16-bit file offset")
		}
		offset := uint16(len(data))
		data = append(data, encoded...)
		data = append(data, 0)
		return offset, nil
	}
	nameOffset, err := text(name)
	if err != nil {
		return nil, err
	}
	show := uint16(2)
	if visible {
		show = 1
	}
	put(8, show)
	for i, value := range []uint16{12, 12, 588, 232, uint16(8 + index%5*110), uint16(320 - index/5*40), nameOffset, 32, 32} {
		put(10+2*i, value)
	}
	data[28], data[29] = 4, 1
	put(32, uint16(len(items)))

	for i, item := range items {
		icon, err := programGroupIcon(item.icon)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", item.name, err)
		}
		if len(data)+groupItemSize+len(icon) > math.MaxUint16 || item.iconIndex < 0 || item.iconIndex > math.MaxUint16 {
			return nil, fmt.Errorf("invalid program group item %q", item.name)
		}
		pos := len(data)
		put(groupHeaderSize+2*i, uint16(pos))
		data = append(data, make([]byte, groupItemSize)...)
		iconOffset := uint16(len(data))
		data = append(data, icon...)
		const andBytes = groupIconSize * groupIconSize / 8
		const xorBytes = groupIconSize * groupIconSize / 2
		for offset, value := range []uint16{uint16(20 + i%5*105), uint16(12 + i/5*60), uint16(item.iconIndex), 12, andBytes, xorBytes, iconOffset, iconOffset + 12, iconOffset + 12 + andBytes} {
			put(pos+offset*2, value)
		}
		for offset, value := range []string{item.name, item.command, item.iconPath} {
			pointer, err := text(value)
			if err != nil {
				return nil, err
			}
			put(pos+18+2*offset, pointer)
		}
	}
	if len(data)%2 != 0 {
		if len(data) == math.MaxUint16 {
			return nil, fmt.Errorf("program group checksum padding exceeds the file limit")
		}
		data = append(data, 0)
	}
	put(6, uint16(len(data)))
	var checksum uint16
	for offset := 0; offset < len(data); offset += 2 {
		checksum += binary.LittleEndian.Uint16(data[offset:])
	}
	put(4, -checksum)
	return data, nil
}

// programGroupIcon converts the 32x32 16-color DIBs carried by the original
// Win16 executables. PMCC embeds word-aligned, top-down device bitmap masks.
func programGroupIcon(dib []byte) ([]byte, error) {
	const colorTable = 40
	const xorStart = colorTable + 16*4
	const xorStride = groupIconSize / 2
	const andStride = groupIconSize / 8
	const andStart = xorStart + groupIconSize*xorStride
	if len(dib) < andStart+groupIconSize*andStride || binary.LittleEndian.Uint32(dib) != colorTable ||
		binary.LittleEndian.Uint32(dib[4:]) != groupIconSize || binary.LittleEndian.Uint32(dib[8:]) != 2*groupIconSize ||
		binary.LittleEndian.Uint32(dib[12:]) != 0x00040001 || binary.LittleEndian.Uint32(dib[16:]) != 0 {
		return nil, fmt.Errorf("expected an uncompressed 32×32 four-bit Win16 icon")
	}
	const header = 12
	icon := make([]byte, header+groupIconSize*(andStride+xorStride))
	binary.LittleEndian.PutUint16(icon[4:], groupIconSize)
	binary.LittleEndian.PutUint16(icon[6:], groupIconSize)
	binary.LittleEndian.PutUint16(icon[8:], xorStride)
	icon[10], icon[11] = 1, 4
	for y := range groupIconSize {
		row := groupIconSize - 1 - y
		copy(icon[header+y*andStride:], dib[andStart+row*andStride:andStart+(row+1)*andStride])
		copy(icon[header+groupIconSize*andStride+y*xorStride:], dib[xorStart+row*xorStride:xorStart+(row+1)*xorStride])
	}
	return icon, nil
}
