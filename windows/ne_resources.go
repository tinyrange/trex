package windows

import (
	"bytes"
	"encoding/binary"
	"fmt"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

// neImageResources validates the executable envelope before using the same
// native NE table reader as windows.icon; there is no second table parser.
func neImageResources(data []byte) ([]peResource, error) {
	if len(data) < 64 || string(data[:2]) != "MZ" {
		return nil, fmt.Errorf("ne_resources: missing DOS header")
	}
	base := uint64(binary.LittleEndian.Uint32(data[0x3c:]))
	if base > uint64(len(data)) || uint64(len(data))-base < 64 {
		return nil, fmt.Errorf("ne_resources: NE header outside file")
	}
	if string(data[base:base+2]) != "NE" {
		return nil, fmt.Errorf("ne_resources: missing NE signature")
	}
	return neResources(data, int(base))
}

// Win16 VERSIONINFO has a byte-string key and no Win32 wType member.
func parseNEFixedVersion(data []byte) (peFixedVersion, bool) {
	var out peFixedVersion
	if len(data) < 4 {
		return out, false
	}
	total := int(binary.LittleEndian.Uint16(data))
	valueLen := int(binary.LittleEndian.Uint16(data[2:]))
	key := []byte("VS_VERSION_INFO\x00")
	offset := (4 + len(key) + 3) &^ 3
	if total > len(data) || total < offset+52 || valueLen < 52 || valueLen > total-offset || !bytes.Equal(data[4:4+len(key)], key) {
		return out, false
	}
	if binary.LittleEndian.Uint32(data[offset:]) != 0xfeef04bd {
		return out, false
	}
	parts := func(off int) [4]uint16 {
		ms := binary.LittleEndian.Uint32(data[off:])
		ls := binary.LittleEndian.Uint32(data[off+4:])
		return [4]uint16{uint16(ms >> 16), uint16(ms), uint16(ls >> 16), uint16(ls)}
	}
	out.file = parts(offset + 8)
	out.product = parts(offset + 16)
	out.flagsMask = binary.LittleEndian.Uint32(data[offset+24:])
	out.flags = binary.LittleEndian.Uint32(data[offset+28:])
	out.os = binary.LittleEndian.Uint32(data[offset+32:])
	out.fileType = binary.LittleEndian.Uint32(data[offset+36:])
	out.fileSubtype = binary.LittleEndian.Uint32(data[offset+40:])
	return out, true
}

// ne_resources(file) is a strict read-only inspection primitive, not a loader.
// Each row includes raw bytes and optional decoded Win16 fixed-version fields.
func neResourcesBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("ne_resources", args, kwargs, "file", &value); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("ne_resources: got %s, want file", value.Type())
	}
	data, err := starfile.ReadAll(file)
	if err != nil {
		return nil, err
	}
	resources, err := neImageResources(data)
	if err != nil {
		return nil, err
	}
	rows := make([]starlark.Value, 0, len(resources))
	for _, r := range resources {
		var version starlark.Value = starlark.None
		if r.typ == "#16" {
			if v, ok := parseNEFixedVersion(r.data); ok {
				parts := func(p [4]uint16) starlark.Value {
					return starlark.NewList([]starlark.Value{starlark.MakeUint(uint(p[0])), starlark.MakeUint(uint(p[1])), starlark.MakeUint(uint(p[2])), starlark.MakeUint(uint(p[3]))})
				}
				version = starfile.NewRecord(map[string]starlark.Value{"file": parts(v.file), "product": parts(v.product), "flags_mask": starlark.MakeUint(uint(v.flagsMask)), "flags": starlark.MakeUint(uint(v.flags)), "os": starlark.MakeUint(uint(v.os)), "type": starlark.MakeUint(uint(v.fileType)), "subtype": starlark.MakeUint(uint(v.fileSubtype))})
			}
		}
		rows = append(rows, starfile.NewRecord(map[string]starlark.Value{"type": starlark.String(r.typ), "name": starlark.String(r.name), "size": starlark.MakeInt(len(r.data)), "data": starlark.Bytes(r.data), "version": version}))
	}
	return starlark.NewList(rows), nil
}
